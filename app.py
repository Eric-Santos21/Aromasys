from flask import Flask, render_template, url_for, request, redirect, flash

# 1. Configuração do App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua-chave-secreta-aqui'

# 2. Dados Falsos (Mock)
# O caminho AGORA é "imagens/egeo.jpg" para corresponder à pasta
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
    {
        "id": 2,
        "name": "Floratta",
        "description": "Blue Desodorante Colônia 75ml",
        "old_price": 159.90,
        "price": 90.90,
        "installments": "4x R$ 22,73",
        "image_url": "imagens/floratta.jpg",
        "tag": "-43%"
    },
    {
        "id": 3,
        "name": "Match.",
        "description": "Leave-In Reconstrutor 150ml",
        "old_price": 54.90,
        "price": 26.90,
        "installments": "a vista",
        "image_url": "imagens/match.jpg",
        "tag": "-51%"
    },
    {
        "id": 4,
        "name": "Botik",
        "description": "Gel Creme Multiprotetor FPS50 40g",
        "old_price": 87.90,
        "price": 43.90,
        "installments": "2x R$ 21,95",
        "image_url": "imagens/botik.jpg",
        "tag": "-60%"
    },
]
mock_cart_items = [
    {
        "id": 1,
        "name": "Egeo",
        "description": "Cogu Desodorante Colônia 90ml",
        "price": 61.90,
        "quantity": 1,
        "image_url": "imagens/egeo.jpg"
    },
    {
        "id": 3,
        "name": "Match.",
        "description": "Leave-In Reconstrutor 150ml",
        "price": 26.90,
        "quantity": 2,
        "image_url": "imagens/match.jpg"
    }
]
mock_orders = [
    {
        "id": "#123456",
        "date": "14 de nov, 2025",
        "status": "Entregue",
        "total": 103.80,
        "items": [
            { "name": "Egeo - Cogu Desodorante Colônia 90ml", "image_url": "imagens/egeo.jpg" }, # CORREÇÃO AQUI
            { "name": "Match. - Leave-In Reconstrutor 150ml", "image_url": "imagens/match.jpg" }
        ]
    },
    {
        "id": "#123112",
        "date": "05 de out, 2025",
        "status": "Cancelado",
        "total": 90.90,
        "items": [
            { "name": "Floratta - Blue Desodorante Colônia 75ml", "image_url": "imagens/floratta.jpg" }
        ]
    }
]

# 3. Definição das Rotas (PAINEL USUÁRIO)

@app.route("/")
def home():
    return render_template("index.html", products=mock_products)

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/cadastrar")
def cadastrar():
    return render_template("cadastrar.html")

@app.route("/carrinho")
def carrinho():
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
def perfil():
    return render_template("perfil.html", orders=mock_orders)

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
# 4. Definição das Rotas (PAINEL ADMIN)
# ===================================

@app.route("/admin/login")
def admin_login():
    return render_template("admin_login.html")

@app.route("/admin")
@app.route("/admin/dashboard")
def admin_dashboard():
    return render_template("admin_dashboard.html", orders=mock_orders)

@app.route("/admin/produtos")
def admin_produtos():
    return render_template("admin_produtos.html", products=mock_products)

@app.route("/admin/pedidos")
def admin_pedidos():
    return render_template("admin_pedidos.html", orders=mock_orders)


# 5. Roda o Aplicativo
if __name__ == "__main__":
    app.run(debug=True)