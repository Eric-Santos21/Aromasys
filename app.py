# ===================================
# 1. IMPORTAÇÕES E CONFIGURAÇÃO INICIAL
# ===================================
import os
from dotenv import load_dotenv
from flask import Flask, render_template, url_for, request, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt

load_dotenv() # Carrega as variáveis do .env

app = Flask(__name__)

# Configuração da Chave Secreta (lendo do .env)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Configuração do Banco de Dados MySQL (lendo do .env)
# Se você instalou 'PyMySQL':
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
# Se você instalou 'mysqlclient':
# app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ===================================
# 2. INICIALIZAÇÃO DAS EXTENSÕES
# ===================================
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

# Define para onde o Flask-Login redireciona se um usuário anônimo
# tentar acessar uma página protegida (ex: /perfil)
login_manager.login_view = 'login'
# (Opcional) Melhora a mensagem de "acesso negado"
login_manager.login_message = 'Por favor, faça login para acessar esta página.'
login_manager.login_message_category = 'info' # (usa a categoria do 'flash')


@login_manager.user_loader
def load_user(user_id):
    """Função necessária para o Flask-Login recarregar o usuário da sessão."""
    return User.query.get(int(user_id))

# ===================================
# 3. DEFINIÇÃO DOS MODELOS (TABELAS)
# ===================================

# UserMixin é necessário para o Flask-Login funcionar
class User(db.Model, UserMixin):
    __tablename__ = 'users' # Nome da tabela
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    cpf = db.Column(db.String(14), unique=True, nullable=False) # ex: 123.456.789-00
    telefone = db.Column(db.String(15), nullable=True) # ex: (83) 91234-5678
    password_hash = db.Column(db.String(60), nullable=False) # Hash de 60 chars do Bcrypt

    # Relação: Um usuário pode ter vários pedidos
    orders = db.relationship('Order', backref='user', lazy=True)

    def set_password(self, password):
        """Cria um hash seguro para a senha."""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Verifica se a senha fornecida bate com o hash."""
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
    
    # Chave Estrangeira: Linka o pedido ao usuário
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relação: Um pedido tem vários itens
    items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    
    # Chaves Estrangeiras
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    
    # Relação (opcional): Linka este item de volta ao objeto Produto
    product = db.relationship('Product')


# ===================================
# 4. DADOS MOCK (Serão removidos)
# ===================================
# Estes dados mock agora serão substituídos por consultas ao banco de dados,
# mas vamos mantê-los por enquanto para as rotas que ainda não foram migradas.

mock_products = [
    {
        "id": 1,
        "name": "Egeo",
        "description": "Cogu Desodorante Colônia 90ml",
        "old_price": 154.90,
        "price": 61.90,
        "installments": "3x R$ 20,63",
        "image_url": "imagens/egeo.jpg",
        "tag": "-60%"
    },
    # ... (o resto dos seus mocks)
]
mock_cart_items = [
    # ... (o resto dos seus mocks)
]
mock_orders = [
    # ... (o resto dos seus mocks)
]


# ===================================
# 5. ROTAS (PAINEL USUÁRIO)
# ===================================

@app.route("/")
def home():
    # AGORA: Substituímos o mock por uma consulta ao banco!
    try:
        products_from_db = Product.query.all()
        return render_template("index.html", products=products_from_db)
    except Exception as e:
        # Se o banco falhar (ex: tabela não existe), use o mock
        flash(f"Erro ao conectar no banco de dados. Usando dados mock. Erro: {e}", "danger")
        return render_template("index.html", products=mock_products)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # (LÓGICA DE LOGIN AINDA NÃO IMPLEMENTADA)
        # 1. Pegar email e senha do form
        # 2. Buscar usuário no banco: user = User.query.filter_by(email=email_do_form).first()
        # 3. Verificar senha: if user and user.check_password(senha_do_form):
        # 4. Logar usuário: login_user(user)
        # 5. Redirecionar: return redirect(url_for('perfil'))
        flash("Lógica de login ainda em construção!", "info")
        return redirect(url_for('login'))
        
    return render_template("login.html")

@app.route("/cadastrar", methods=['GET', 'POST'])
def cadastrar():
    if request.method == 'POST':
        # (LÓGICA DE CADASTRO AINDA NÃO IMPLEMENTADA)
        # 1. Pegar dados do form (nome, email, cpf, senha)
        # 2. Verificar se email/cpf já existem
        # 3. Criar hash da senha: new_user.set_password(senha_do_form)
        # 4. Salvar no banco: db.session.add(new_user); db.session.commit()
        # 5. Redirecionar: return redirect(url_for('login'))
        flash("Lógica de cadastro ainda em construção!", "info")
        return redirect(url_for('cadastrar'))

    return render_template("cadastrar.html")


@app.route("/carrinho")
def carrinho():
    # A lógica do carrinho deve usar a `session` do Flask,
    # não o mock_cart_items
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
@login_required # <-- Protege a rota! Só entra quem está logado.
def perfil():
    # AGORA: Buscaria os pedidos do usuário logado (current_user)
    # orders = Order.query.filter_by(user_id=current_user.id).all()
    # Por enquanto, usamos o mock:
    return render_template("perfil.html", orders=mock_orders)


# ... (Restante das rotas de checkout, sucesso, admin) ...
# (As rotas do admin /admin/produtos e /admin/pedidos também
# devem ser atualizadas para usar Product.query.all() e Order.query.all()
# no lugar dos mocks.)

@app.route("/checkout/confirmacao")
def confirmacao():
    return render_template("confirmacao.html")

@app.route("/checkout/pagamento")
def pagamento():
    return render_template("pagamento.html")

@app.route("/checkout/sucesso")
def sucesso():
    return render_template("sucesso.html")

# ===================================
# 6. ROTAS (PAINEL ADMIN)
# ===================================
@app.route("/admin/login")
def admin_login():
    return render_template("admin_login.html")

@app.route("/admin")
@app.route("/admin/dashboard")
def admin_dashboard():
    # Deveria buscar pedidos do banco
    return render_template("admin_dashboard.html", orders=mock_orders)

@app.route("/admin/produtos")
def admin_produtos():
    # AGORA: Substituímos o mock por uma consulta ao banco!
    try:
        products_from_db = Product.query.all()
        return render_template("admin_produtos.html", products=products_from_db)
    except:
        return render_template("admin_produtos.html", products=mock_products)


@app.route("/admin/pedidos")
def admin_pedidos():
    # Deveria buscar pedidos do banco
    return render_template("admin_pedidos.html", orders=mock_orders)


# ===================================
# 7. RODA O APLICATIVO
# ===================================
if __name__ == "__main__":
    # Comando especial para criar as tabelas no banco de dados
    # (Execute `python app.py create_db` UMA VEZ no terminal)
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'create_db':
        with app.app_context():
            print("Criando tabelas no banco de dados...")
            db.create_all()
            print("Tabelas criadas com sucesso!")
    else:
        app.run(debug=True)