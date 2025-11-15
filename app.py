# ===================================
# 1. IMPORTAÇÕES E CONFIGURAÇÃO INICIAL
# ===================================
import os
from dotenv import load_dotenv
from flask import Flask, render_template, url_for, request, redirect, flash, session, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth # Para o Google Login

load_dotenv() # Carrega as variáveis do .env

app = Flask(__name__)

# Configuração da Chave Secreta (lendo do .env)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Configuração do Banco de Dados MySQL (lendo do .env)
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ===================================
# 2. INICIALIZAÇÃO DAS EXTENSÕES
# ===================================
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
oauth = OAuth(app) # INICIALIZA O OAUTH

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
mock_cart_items = [
    { "id": 1, "name": "Egeo", "description": "Cogu Desodorante Colônia 90ml", "price": 61.90, "quantity": 1, "image_url": "imagens/egeo.jpg" },
    { "id": 3, "name": "Match.", "description": "Leave-In Reconstrutor 150ml", "price": 26.90, "quantity": 2, "image_url": "imagens/match.jpg" }
]
mock_orders = [
    { "id": "#123456", "date": "14 de nov, 2025", "status": "Entregue", "total": 103.80, "items": [ { "name": "Egeo", "image_url": "imagens/egeo.jpg" }, { "name": "Match.", "image_url": "imagens/match.jpg" } ] },
    { "id": "#123112", "date": "05 de out, 2025", "status": "Cancelado", "total": 90.90, "items": [ { "name": "Floratta", "image_url": "imagens/floratta.jpg" } ] }
]

# ===================================
# 6. ROTAS (PAINEL USUÁRIO)
# ===================================

@app.route("/")
def home():
    # Tenta buscar produtos do banco, se falhar, usa o mock
    try:
        products_from_db = Product.query.all()
        return render_template("index.html", products=products_from_db)
    except Exception as e:
        flash(f"Erro ao conectar no banco de dados. Usando dados mock. Erro: {e}", "danger")
        # Se der erro, usa o mock_products (definido no app.py original)
        return render_template("index.html", products=[]) # Você pode adicionar o mock_products aqui se quiser

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
            return redirect(url_for('perfil'))
        else:
            flash("Email ou senha inválidos.", "danger")
            return redirect(url_for('login'))
        
    return render_template("login.html")

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
        flash(f"Erro ao autenticar com o Google: {e}", "danger")
        return redirect(url_for('login'))

    user_info = oauth.google.userinfo(token=token)
    user = User.query.filter_by(email=user_info.email).first()
    
    if user:
        # Usuário já existe, faça login
        login_user(user)
        flash(f"Login feito com sucesso como {user.nome}!", "success")
        return redirect(url_for('perfil'))
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
            # Redireciona para o perfil, onde ele pode preencher o resto
            return redirect(url_for('perfil')) 
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
        
        # TODO: Adicionar validação (ex: senha_confere, email/cpf já existe)
        
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
    # TODO: Lógica do carrinho deve usar a `session`, não o mock
    subtotal = sum(item['price'] * item['quantity'] for item in mock_cart_items)
    frete = 15.00 if subtotal > 0 else 0
    total = subtotal + frete
    return render_template(
        "carrinho.html",
        cart_items=mock_cart_items,
        subtotal=subtotal,
        frete=frete,
        total=total
    )

@app.route("/perfil")
@login_required # Protege a rota!
def perfil():
    # TODO: Buscar pedidos do usuário logado:
    # orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template("perfil.html", orders=mock_orders)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logout realizado com sucesso.", "success")
    return redirect(url_for('home'))

@app.route("/checkout/confirmacao")
@login_required
def confirmacao():
    return render_template("confirmacao.html")

@app.route("/checkout/pagamento")
@login_required
def pagamento():
    return render_template("pagamento.html")

@app.route("/checkout/sucesso")
@login_required
def sucesso():
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
def admin_dashboard():
    # TODO: Buscar pedidos do banco
    return render_template("admin_dashboard.html", orders=mock_orders)

@app.route("/admin/produtos")
# @login_required (Adicionar verificação se é admin)
def admin_produtos():
    try:
        products_from_db = Product.query.all()
        return render_template("admin_produtos.html", products=products_from_db)
    except Exception as e:
        flash(f"Erro ao buscar produtos: {e}", "danger")
        return render_template("admin_produtos.html", products=[])


@app.route("/admin/pedidos")
# @login_required (Adicionar verificação se é admin)
def admin_pedidos():
    # TODO: Buscar pedidos do banco
    return render_template("admin_pedidos.html", orders=mock_orders)


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
        app.run(debug=True)