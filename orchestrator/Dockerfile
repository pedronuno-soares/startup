# Usar a imagem oficial do Node.js leve
FROM node:18-alpine

# Criar diretório de trabalho dentro do contentor
WORKDIR /usr/src/app

# Copiar os ficheiros de dependências primeiro (otimiza o cache do Docker)
COPY package*.json ./

# Instalar dependências
RUN npm install

# Copiar o resto do código da aplicação
COPY . .

# Compilar o código TypeScript para JavaScript
RUN npm run build

# Expor a porta que definimos no docker-compose (8080)
EXPOSE 8080

# Comando para iniciar o servidor
CMD ["npm", "start"]