const fs = require('fs');
const content = fs.readFileSync('c:/Users/ruben/OneDrive/Ambiente de Trabalho/StartUp (2)/StartUp (2)/StartUp (1)/StartUp/orchestrator/src/routes/auth.ts', 'utf8');

// Strip out any weird null bytes
let clean = content.replace(/\0/g, '');

// Split by line and keep only the first 250 lines
const lines = clean.split('\n').slice(0, 250);

// Fix the email validation and the Ruben email
let result = lines.join('\n');
result = result.replace(/RÃºben/g, 'ruben@policia.pt');
result = result.replace(/Rúben/g, 'ruben@policia.pt');

const emailRegexStr = `        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                error:   'InvalidEmail',
                message: 'Formato de email inválido.',
            });
        }`;

result = result.replace(/\/\/ Validacao de email removida.*/g, emailRegexStr);

fs.writeFileSync('c:/Users/ruben/OneDrive/Ambiente de Trabalho/StartUp (2)/StartUp (2)/StartUp (1)/StartUp/orchestrator/src/routes/auth.ts', result, 'utf8');
console.log('Fixed auth.ts');
