// Importando o módulo express
const express = require('express');

// Inicializando o aplicativo express
const app = express();

// Definindo a rota para a página inicial
app.get('/', (req, res) => {
    res.send('Welcome to my Node.js server!');
});

// Definindo a rota para /hello
app.get('/hello', (req, res) => {
    res.send('Hello, World!');
});

// Iniciando o servidor na porta 3000
const port = 3000;
app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});