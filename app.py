# ===================================
# 1. IMPORTAÇÕES E CONFIGURAÇÃO INICIAL
# ===================================
import os
import uuid
from dotenv import load_dotenv
from flask import Flask, render_template, url_for, request, redirect, flash, session, g, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth # Para o Google Login
from sqlalchemy.exc import OperationalError
import logging
import random
import string
import re

load_dotenv() # Carrega as variáveis do .env

# Identificador único desta instância do servidor (troca ao reiniciar)
SERVER_ID = uuid.uuid4().hex

app = Flask(__name__)

# ----------------------
# Filtros Jinja de formatação
# ----------------------
@app.template_filter('format_cpf')
def format_cpf(value: str):
    """Converte '12345678901' em '123.456.789-01'."""
    if not value:
        return ''
    digits = re.sub(r'\D', '', value)
    if len(digits) != 11:
        return value  # comprimento inesperado
    return f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:]}"

@app.template_filter('format_phone')
def format_phone(value: str):
    """Converte '86940028922' em '(86) 94002-8922'. Aceita 10 ou 11 dígitos."""
    if not value:
        return ''
    digits = re.sub(r'\D', '', value)
    if len(digits) == 11:
        return f"({digits[:2]}) {digits[2:7]}-{digits[7:]}"
    if len(digits) == 10:
        return f"({digits[:2]}) {digits[2:6]}-{digits[6:]}"
    return value

# Configuração da Chave Secreta (lendo do .env)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Configuração do Banco de Dados MySQL (lendo do .env)
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Exibe as queries SQL no console para debug
app.config['SQLALCHEMY_ECHO'] = False

# ===================================
# 2. INICIALIZAÇÃO DAS EXTENSÕES
# ===================================
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
oauth = OAuth(app) # INICIALIZA O OAUTH

# Torna a sessão não permanente: cookie é apagado ao fechar o navegador
@app.before_request
def manage_session():
    # Cookie some como "session" (apaga ao fechar navegador)
    session.permanent = False
    # Se o cookie foi gerado numa instância antiga do servidor, limpa carrinho
    if session.get('server_id') != SERVER_ID:
        session.pop('cart', None)
        session['server_id'] = SERVER_ID

# Define para onde o Flask-Login redireciona
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    """Função necessária para o Flask-Login recarregar o usuário da sessão."""
    return User.query.get(int(user_id))

# ===================================
# 3. DEFINIÇÃO DOS MODELOS (TABELAS)
# ===================================

# UserMixin é necessário para o Flask-Login
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    
    # CORREÇÃO PARA GOOGLE: Estes campos podem ser nulos
    cpf = db.Column(db.String(14), unique=True, nullable=True) 
    telefone = db.Column(db.String(15), nullable=True)
    enderecos = db.Column(db.String(150), nullable=True)
    password_hash = db.Column(db.String(60), nullable=True) # Senha nula se for login Google

    # Relação: Um usuário pode ter vários pedidos
    orders = db.relationship('Order', backref='user', lazy=True)

    def set_password(self, password):
        """Cria um hash seguro para a senha."""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Verifica se a senha fornecida bate com o hash."""
        # Garante que o hash não seja nulo (contas Google não têm hash)
        if not self.password_hash:
            return False
        return bcrypt.check_password_hash(self.password_hash, password)

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    old_price = db.Column(db.Float, nullable=True)
    price = db.Column(db.Float, nullable=False)
    installments = db.Column(db.String(50), nullable=True)
    image_url = db.Column(db.String(200), nullable=True) # Caminho da imagem
    tag = db.Column(db.String(20), nullable=True) # Ex: "-60%"

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    order_ref = db.Column(db.String(20), unique=True, nullable=False) # Ex: "#123456"
    date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    status = db.Column(db.String(50), nullable=False, default='Processando')
    total = db.Column(db.Float, nullable=False)
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    
    product = db.relationship('Product')


# ===================================
# 4. CONFIGURAÇÃO DO GOOGLE OAUTH
# ===================================
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# ===================================
# 5. DADOS MOCK (Para rotas não prontas)
# ===================================
mock_orders = [
    { "id": "#123456", "date": "14 de nov, 2025", "status": "Entregue", "total": 103.80, "items": [ { "name": "Egeo", "image_url": "imagens/egeo.jpg" }, { "name": "Match.", "image_url": "imagens/match.jpg" } ] },
    { "id": "#123112", "date": "05 de out, 2025", "status": "Cancelado", "total": 90.90, "items": [ { "name": "Floratta", "image_url": "imagens/floratta.jpg" } ] }
]

# ===================================
# 5.1. FUNÇÃO DE INICIALIZAÇÃO DO BANCO
# ===================================

def initialize_database():
    """Cria tabelas e insere produtos de exemplo se o banco estiver vazio."""
    with app.app_context():
        try:
            db.create_all()
        except OperationalError as e:
            print(f"Falha ao conectar/criar tabelas: {e}")
            return

        # Insere produtos padrão apenas se a tabela estiver vazia
        if Product.query.count() == 0:
            sample_products = [
                {
                    "name": "Egeo",
                    "description": "Colônia 90ml",
                    "old_price": 89.90,
                    "price": 61.90,
                    "installments": "3x de 20,63",
                    "image_url": "imagens/egeo.jpg",
                    "tag": "-30%"
                },
                {
                    "name": "Match.",
                    "description": "Leave-In Reconstrutor 150ml",
                    "old_price": None,
                    "price": 26.90,
                    "installments": "2x de 13,45",
                    "image_url": "imagens/match.jpg",
                    "tag": None
                }
            ]
            for item in sample_products:
                db.session.add(Product(**item))
            db.session.commit()
            print("Banco inicializado com dados de exemplo.")

# ===================================
# 6. ROTAS (PAINEL USUÁRIO)
# ===================================
@app.route("/")
def home():
    # 1. Pega o termo digitado na busca (se existir)
    search_query = request.args.get('q')

    try:
        if search_query:
            # 2. Se tiver busca, filtra o banco (LIKE %texto%)
            # O filtro busca produtos onde o nome CONTÉM o texto digitado
            products_from_db = Product.query.filter(Product.name.like(f'%{search_query}%')).all()
            
            # Dica: Se quiser buscar na descrição também, seria algo mais avançado,
            # mas por enquanto vamos buscar só pelo nome.
        else:
            # 3. Se não tiver busca, traz todos (comportamento padrão)
            products_from_db = Product.query.all()
            
        return render_template("index.html", products=products_from_db)
        
    except Exception as e:
        flash(f"Erro ao conectar no banco de dados. Erro: {e}", "danger")
        return render_template("index.html", products=[])

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Lógica de login com Email/Senha
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash("Login feito com sucesso!", "success")
            return redirect(url_for('home'))
        else:
            flash("Email ou senha inválidos.", "danger")
            return redirect(url_for('login'))
        
    return render_template("login.html")

# --- ROTA ADD TO CART ---
@app.route("/carrinho/add/<int:product_id>", methods=["POST"])
def add_to_cart(product_id):
    """Incrementa em 1 a quantidade de um produto no carrinho."""
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Produto não encontrado'}), 404
    cart = session.get('cart', {})
    cart[str(product_id)] = cart.get(str(product_id), 0) + 1
    session['cart'] = cart
    return jsonify({'status': 'added', 'cart_count': sum(cart.values())})

# --- ROTA UPDATE CART ---
@app.route("/carrinho/update", methods=["POST"])
def update_cart():
    """Atualiza a quantidade de um item ou remove-o se quantity == 0."""
    data = request.get_json(silent=True) or {}
    product_id = str(data.get('product_id'))
    if not product_id:
        return jsonify({'error': 'Produto inválido'}), 400

    try:
        quantity = int(data.get('quantity', 1))
    except (TypeError, ValueError):
        return jsonify({'error': 'Quantidade inválida'}), 400

    cart = session.get('cart', {})

    if quantity > 0:
        cart[product_id] = quantity
    else:
        # quantity <= 0 remove o item
        cart.pop(product_id, None)

    session['cart'] = cart
    return jsonify({'status': 'updated', 'cart_count': sum(cart.values())})

# --- NOVAS ROTAS GOOGLE ---
@app.route("/login/google")
def login_google():
    """Redireciona o usuário para a tela de login do Google."""
    redirect_uri = url_for('google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/google/callback")
def google_callback():
    """Página que recebe a resposta do Google."""
    try:
        token = oauth.google.authorize_access_token()
    except Exception as e:
        app.logger.error("Google OAuth error: %s", e, exc_info=True)
        flash("Falha na autenticação com o Google. Tente novamente mais tarde.", "danger")
        return redirect(url_for('login'))

    user_info = oauth.google.userinfo(token=token)
    user = User.query.filter_by(email=user_info.email).first()
    
    if user:
        # Usuário já existe, faça login
        login_user(user)
        flash(f"Login feito com sucesso como {user.nome}!", "success")
        return redirect(url_for('home'))
    else:
        # Usuário não existe, crie uma nova conta
        new_user = User(
            email=user_info.email,
            nome=user_info.name
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash("Conta criada com sucesso via Google!", "success")
            return redirect(url_for('home')) 
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao criar conta: {e}", "danger")
            return redirect(url_for('login'))
# --- FIM DAS ROTAS GOOGLE ---

@app.route("/cadastrar", methods=['GET', 'POST'])
def cadastrar():
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        cpf = request.form.get('cpf')
        telefone = request.form.get('telefone')
        password = request.form.get('password')
        
        new_user = User(nome=nome, email=email, cpf=cpf, telefone=telefone)
        new_user.set_password(password) # Cria o hash da senha

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Conta criada com sucesso! Faça o login.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao criar conta (email ou CPF já pode existir): {e}", "danger")
            return redirect(url_for('cadastrar'))

    return render_template("cadastrar.html")


@app.route("/carrinho")
def carrinho():
    cart = session.get('cart', {})  # {product_id: qty}
    cart_items = []
    subtotal = 0
    for pid_str, qty in cart.items():
        product = Product.query.get(int(pid_str))
        if product:
            cart_items.append({
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'quantity': qty,
                'image_url': product.image_url or ''
            })
            subtotal += product.price * qty
    frete = 15.00 if subtotal > 0 else 0
    total = subtotal + frete
    return render_template(
        "carrinho.html",
        cart_items=cart_items,
        subtotal=subtotal,
        frete=frete,
        total=total
    )


# -----------------------------
# ROTA PERFIL (CORRIGIDA)
# -----------------------------
@app.route("/perfil/endereco/delete", methods=['POST'])
@login_required
def excluir_endereco():
    """Remove o endereço salvo do usuário"""
    current_user.enderecos = None
    try:
        db.session.commit()
        # Resposta Ajax
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=True)
        flash('Endereço removido com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=False, error=str(e)), 500
        flash('Erro ao remover endereço.', 'danger')
    return redirect(url_for('perfil', tab='enderecos-pane'))


@app.route("/perfil", methods=['GET', 'POST'])
@login_required
def perfil():
    if request.method == 'POST':
        # Coleta dados que podem ou não estar presentes dependendo do formulário
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip()

        # Sanitiza CPF e telefone: mantém apenas dígitos
        cpf_raw = request.form.get('cpf', '').strip()
        telefone_raw = request.form.get('telefone', '').strip()
        rua = request.form.get('rua', '').strip()
        numero = request.form.get('numero', '').strip()
        complemento = request.form.get('complemento', '').strip()

        endereco_str = None
        if rua or numero or complemento:
            endereco_str = f"{rua}, {numero}" if numero else rua
            if complemento:
                endereco_str += f" - {complemento}"

        cpf = re.sub(r'\D', '', cpf_raw) if cpf_raw else None
        telefone = re.sub(r'\D', '', telefone_raw) if telefone_raw else None

        # Atualiza objeto usuário APENAS se o valor foi enviado
        if nome:
            current_user.nome = nome
        if email:
            current_user.email = email
        if cpf is not None:
            current_user.cpf = cpf
        if telefone is not None:
            current_user.telefone = telefone
        if endereco_str is not None:
            current_user.enderecos = endereco_str

        try:
            db.session.commit()
            # Se for chamada via fetch/AJAX retorna JSON para atualização dinâmica
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify(success=True, address=current_user.enderecos or '')
            flash('Dados atualizados com sucesso!', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error('Erro ao atualizar perfil: %s', e, exc_info=True)
            flash('Erro ao salvar dados. Tente novamente.', 'danger')
        
        # Redireciona de volta se existia next salvo
        next_url = session.pop('next_after_profile', None)
        if next_url:
            return redirect(next_url)
        return redirect(url_for('perfil'))
    
    # --- Requisição GET ---
    # Permite selecionar aba inicial via query string ?tab=...
    initial_tab = request.args.get('tab', '')

    # Busca pedidos do usuário (pode ser exibido na área "Meus Pedidos")
    user_orders = Order.query.filter_by(user_id=current_user.id).all()

    return render_template('perfil.html', initial_tab=initial_tab, orders=user_orders)


@app.route("/logout")
@login_required
def logout():
    # Limpa a sacola salva na sessão
    session.pop('cart', None)
    logout_user()
    # Remove quaisquer mensagens pendentes acumuladas
    session.pop('_flashes', None)
    flash("Logout realizado com sucesso.", "success")
    return redirect(url_for('login'))


# -----------------------------
# ROTA DETALHES DO PEDIDO
# -----------------------------
@app.route("/pedido/<int:order_id>")
@login_required
def pedido_detalhes(order_id):
    """Exibe página com detalhes do pedido especificado (apenas do usuário logado)."""
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
    return render_template("pedido_detalhes.html", order=order)

@app.route("/checkout/confirmacao")
@login_required
def confirmacao():
    cart = session.get('cart', {})
    subtotal = 0
    cart_items = []

    for pid_str, qty in cart.items():
        product = Product.query.get(int(pid_str))
        if product:
            item_total = product.price * qty
            subtotal += item_total
            cart_items.append({
                'name': product.name,
                'image_url': product.image_url,
                'price': product.price,
                'quantity': qty
            })
        frete = 15.00 if subtotal > 0 else 0
    total = subtotal + frete
    return render_template(
        "confirmacao.html",
        subtotal=subtotal,
        frete=frete,
        total=total,
        cart_items=cart_items
    )

@app.route("/checkout/pagamento")
@login_required
def pagamento():
    if not current_user.enderecos:
        flash("Cadastre um endereço antes de prosseguir ao pagamento.", "warning")
        return redirect(url_for('confirmacao'))
    return render_template("pagamento.html")

@app.route("/checkout/sucesso")
@login_required
def sucesso():
    cart = session.get('cart', {})
    if cart:
        # Gera referência única simples ex: #A1B2C3
        order_ref = '#' + ''.join(random.choices(string.digits, k=6))
        subtotal = 0
        order_items = []
        for pid_str, qty in cart.items():
            product = Product.query.get(int(pid_str))
            if product:
                subtotal += product.price * qty
                order_items.append(OrderItem(quantity=qty, product_id=product.id))
        if order_items:
            new_order = Order(
                order_ref=order_ref,
                total=subtotal,
                status='Confirmado',
                user_id=current_user.id,
                items=order_items
            )
            try:
                db.session.add(new_order)
                db.session.commit()
                session.pop('cart', None)
            except Exception as e:
                db.session.rollback()
                app.logger.error('Erro ao salvar pedido: %s', e, exc_info=True)
    return render_template("sucesso.html")

# ===================================
# 7. ROTAS (PAINEL ADMIN)
# ===================================

@app.route("/admin/login")
def admin_login():
    # TODO: Lógica de login admin
    return render_template("admin_login.html")

@app.route("/admin")
@app.route("/admin/dashboard")
# @login_required (Adicionar verificação se é admin)
@app.route("/admin")
@app.route("/admin/dashboard")
# @login_required
def admin_dashboard():
    from datetime import datetime
    
    # 1. Pega o primeiro dia do mês atual
    now = datetime.utcnow()
    first_day = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    try:
        # 2. Busca apenas pedidos CONFIRMADOS feitos deste o dia 1
        confirmed_orders = Order.query.filter(
            Order.date >= first_day,
            Order.status == 'Confirmado'
        ).all()
        
        # 3. Conta quantas vendas foram feitas
        vendas_count = len(confirmed_orders)
        
        # 4. Soma o valor total desses pedidos (Isso será exibido como "Lucro")
        lucro_mes = sum(order.total for order in confirmed_orders)
        
        # 5. Busca os últimos 10 pedidos (independente do status) para a tabela
        recent_orders = Order.query.order_by(Order.date.desc()).limit(10).all()
        
    except Exception as e:
        print(f"Erro no dashboard: {e}") # Mostra o erro no terminal para ajudar
        flash("Erro ao calcular dados do painel.", "danger")
        vendas_count = 0
        lucro_mes = 0.0
        recent_orders = []
        
    # Enviamos 'lucro_mes' tanto para o card de Faturamento quanto para o de Lucro
    # já que agora representam a mesma coisa (Total Confirmado)
    return render_template("admin_dashboard.html",
                           vendas_mes=vendas_count,
                           lucro_mes=lucro_mes,     # Total Confirmado
                           faturamento=lucro_mes,   # Total Confirmado
                           orders=recent_orders)

@app.route("/admin/produtos")
# @login_required (Adicionar verificação se é admin)
def admin_produtos():
    try:
        products_from_db = Product.query.all()
        return render_template("admin_produtos.html", products=products_from_db)
    except Exception as e:
        flash(f"Erro ao buscar produtos: {e}", "danger")
        return render_template("admin_produtos.html", products=[])

@app.route("/admin/produtos/novo", methods=["GET", "POST"])
# @login_required (Adicionar verificação se é admin)
def admin_produto_novo():
    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")
        price = request.form.get("price")
        old_price = request.form.get("old_price") or None
        installments = request.form.get("installments")
        image_file = request.files.get("image")
        image_url = None
        if image_file and image_file.filename:
            from werkzeug.utils import secure_filename
            filename = secure_filename(image_file.filename)
            upload_folder = os.path.join(app.root_path, 'static', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            save_path = os.path.join(upload_folder, filename)
            image_file.save(save_path)
            image_url = f'uploads/{filename}'
        tag = request.form.get("tag")

        # Validação simples de preço
        try:
            price = float(price)
            if old_price:
                old_price = float(old_price)
        except ValueError:
            flash("Preço inválido.", "danger")
            return redirect(url_for("admin_produto_novo"))

        new_product = Product(
            name=name,
            description=description,
            price=price,
            old_price=old_price,
            installments=installments,
            image_url=image_url,
            tag=tag
        )
        try:
            db.session.add(new_product)
            db.session.commit()
            flash("Produto cadastrado com sucesso!", "success")
            return redirect(url_for("admin_produtos"))
        except Exception as e:
            db.session.rollback()
            flash(f"Erro ao cadastrar produto: {e}", "danger")
            return redirect(url_for("admin_produto_novo"))

    return render_template("admin_produto_form.html", title="Novo Produto", active_page="produtos")

# --- Excluir produto ---
@app.route("/admin/produtos/<int:prod_id>/delete", methods=["POST"])  # noqa
# @login_required  # habilite se necessário
def admin_produto_delete(prod_id):
    product = Product.query.get_or_404(prod_id)
    try:
        # Remove itens de pedidos que referenciam este produto
        OrderItem.query.filter_by(product_id=product.id).delete()
        db.session.delete(product)
        db.session.commit()
        flash("Produto excluído com sucesso!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao excluir produto: {e}", "danger")
    return redirect(url_for("admin_produtos"))

@app.route("/admin/pedidos")
# @login_required (Adicionar verificação se é admin)
def admin_pedidos():
    try:
        orders = Order.query.order_by(Order.date.desc()).all()
    except Exception as e:
        flash(f"Erro ao buscar pedidos: {e}", "danger")
        orders = []
    return render_template("admin_pedidos.html", orders=orders)

# --- Detalhes do pedido (Admin) ---
@app.route("/admin/pedidos/<int:order_id>")
# @login_required (Adicionar verificação se é admin)
def admin_pedido_detalhes(order_id):
    order = Order.query.get_or_404(order_id)
    return render_template("admin_pedido_detalhes.html", order=order)


# ===================================
# 8. RODA O APLICATIVO
# ===================================

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'create_db':
        with app.app_context():
            print("Criando tabelas no banco de dados...")
            db.create_all()
            print("Tabelas criadas com sucesso!")
    else:
        initialize_database()
        app.run(debug=True)