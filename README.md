# 🔐 Librería Criptográfica en JavaScript

Una librería completa de criptografía en JavaScript que proporciona funciones para hash, cifrado simétrico, asimétrico y codificación de datos.

## 📋 Características

- **Funciones de Hash**: SHA-256, MD5, SHA-1
- **Cifrado Simétrico**: AES-256-CBC (implementación básica y avanzada)
- **Cifrado Asimétrico**: RSA (generación de claves, cifrado/descifrado)
- **Codificación**: Base64, Hexadecimal
- **Utilidades**: Generación de cadenas aleatorias, Salt, Hash de contraseñas con PBKDF2
- **Verificación de contraseñas**: Sistema seguro de verificación

## 🚀 Instalación

```bash
# Instalar dependencias
npm install

# Instalar dependencias de desarrollo
npm install --save-dev jest
```

## 📦 Dependencias

- `crypto-js`: Para funciones criptográficas avanzadas
- `jest`: Para testing (desarrollo)

## 🧪 Ejecutar Tests

```bash
# Ejecutar todos los tests
npm test

# Ejecutar tests en modo watch
npm run test:watch
```

## 🎯 Uso

### Importar la librería

```javascript
const cryptoLib = require('./src/index');
```

## 📚 Ejemplos Prácticos

### Ejemplo 1: Sistema de Autenticación Básico

```javascript
const cryptoLib = require('./src/index');

// Registro de usuario
function registrarUsuario(username, password) {
    const { hash, salt } = cryptoLib.hashPassword(password);
    
    // Simular guardado en base de datos
    const usuario = {
        username: username,
        passwordHash: hash,
        salt: salt,
        fechaRegistro: new Date()
    };
    
    console.log('Usuario registrado:', usuario);
    return usuario;
}

// Login de usuario
function loginUsuario(username, password, usuarioGuardado) {
    const isValid = cryptoLib.verifyPassword(password, usuarioGuardado.passwordHash, usuarioGuardado.salt);
    
    if (isValid) {
        console.log(`✅ Login exitoso para ${username}`);
        return true;
    } else {
        console.log(`❌ Contraseña incorrecta para ${username}`);
        return false;
    }
}

// Ejemplo de uso
const usuario = registrarUsuario('admin', 'miPassword123');
loginUsuario('admin', 'miPassword123', usuario); // ✅ Login exitoso
loginUsuario('admin', 'passwordIncorrecta', usuario); // ❌ Contraseña incorrecta
```

### Ejemplo 2: Cifrado de Documentos Sensibles

```javascript
const cryptoLib = require('./src/index');
const fs = require('fs');

// Cifrar un documento
async function cifrarDocumento(archivoOriginal, archivoCifrado, password) {
    try {
        // Generar hash del archivo original para verificar integridad
        const hashOriginal = await cryptoLib.hashFile(archivoOriginal, 'sha256');
        console.log('Hash original:', hashOriginal);
        
        // Cifrar el archivo
        const resultado = await cryptoLib.encryptFile(archivoOriginal, archivoCifrado, password);
        console.log('Archivo cifrado exitosamente:', resultado);
        
        return { hashOriginal, resultado };
    } catch (error) {
        console.error('Error al cifrar:', error.message);
    }
}

// Descifrar un documento
async function descifrarDocumento(archivoCifrado, archivoDescifrado, password, hashOriginal) {
    try {
        // Descifrar el archivo
        const resultado = await cryptoLib.decryptFile(archivoCifrado, archivoDescifrado, password);
        console.log('Archivo descifrado exitosamente:', resultado);
        
        // Verificar integridad
        const hashDescifrado = await cryptoLib.hashFile(archivoDescifrado, 'sha256');
        const integridadVerificada = hashOriginal === hashDescifrado;
        
        console.log('Hash descifrado:', hashDescifrado);
        console.log('Integridad verificada:', integridadVerificada ? '✅ Sí' : '❌ No');
        
        return { resultado, integridadVerificada };
    } catch (error) {
        console.error('Error al descifrar:', error.message);
    }
}

// Ejemplo de uso
async function ejemploCifrado() {
    const password = 'miPasswordSuperSecreta123';
    
    // Crear archivo de prueba
    fs.writeFileSync('documento.txt', 'Este es un documento confidencial');
    
    // Cifrar
    const { hashOriginal } = await cifrarDocumento('documento.txt', 'documento.enc', password);
    
    // Descifrar
    await descifrarDocumento('documento.enc', 'documento-descifrado.txt', password, hashOriginal);
    
    // Limpiar archivos
    ['documento.txt', 'documento.enc', 'documento-descifrado.txt'].forEach(archivo => {
        if (fs.existsSync(archivo)) fs.unlinkSync(archivo);
    });
}

ejemploCifrado();
```

### Ejemplo 3: Wallet Ethereum Simple

```javascript
const cryptoLib = require('./src/index');

// Crear un wallet Ethereum
function crearWalletEthereum() {
    const keyPair = cryptoLib.generateSecp256k1KeyPair();
    const address = cryptoLib.getEthereumAddress(keyPair.publicKey);
    
    return {
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        address: address
    };
}

// Firmar una transacción
function firmarTransaccion(transaccion, privateKey) {
    const transaccionString = JSON.stringify(transaccion);
    const hashTransaccion = cryptoLib.keccak256(transaccionString);
    
    const signature = cryptoLib.signSecp256k1(hashTransaccion, privateKey);
    
    return {
        transaccion: transaccion,
        hash: hashTransaccion,
        signature: signature.signature,
        recoveryId: signature.recoveryId
    };
}

// Ejemplo de uso
function ejemploWallet() {
    // Crear wallet
    const wallet = crearWalletEthereum();
    console.log('Wallet creado:');
    console.log('Dirección:', wallet.address);
    console.log('Clave privada:', wallet.privateKey);
    
    // Crear transacción
    const transaccion = {
        from: wallet.address,
        to: '0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6',
        value: '1000000000000000000', // 1 ETH en wei
        gas: '21000',
        gasPrice: '20000000000', // 20 gwei
        nonce: 0
    };
    
    // Firmar transacción
    const transaccionFirmada = firmarTransaccion(transaccion, wallet.privateKey);
    console.log('\nTransacción firmada:');
    console.log('Hash:', transaccionFirmada.hash);
    console.log('Firma:', transaccionFirmada.signature);
}

ejemploWallet();
```

### Ejemplo 4: Sistema de Mensajería Segura

```javascript
const cryptoLib = require('./src/index');

// Generar par de claves para comunicación
function generarParClaves() {
    return cryptoLib.generateRSAKeyPair(2048);
}

// Enviar mensaje cifrado
function enviarMensaje(mensaje, clavePublicaDestinatario) {
    const mensajeCifrado = cryptoLib.encryptRSA(mensaje, clavePublicaDestinatario);
    const hashMensaje = cryptoLib.sha256(mensaje);
    
    return {
        mensajeCifrado: mensajeCifrado,
        hash: hashMensaje,
        timestamp: new Date().toISOString()
    };
}

// Recibir y descifrar mensaje
function recibirMensaje(mensajeEnviado, clavePrivadaDestinatario) {
    try {
        const mensajeDescifrado = cryptoLib.decryptRSA(mensajeEnviado.mensajeCifrado, clavePrivadaDestinatario);
        const hashVerificado = cryptoLib.sha256(mensajeDescifrado);
        
        const integridadVerificada = hashVerificado === mensajeEnviado.hash;
        
        return {
            mensaje: mensajeDescifrado,
            integridadVerificada: integridadVerificada,
            timestamp: mensajeEnviado.timestamp
        };
    } catch (error) {
        return {
            error: 'No se pudo descifrar el mensaje',
            integridadVerificada: false
        };
    }
}

// Ejemplo de uso
function ejemploMensajeria() {
    // Generar claves para Alice y Bob
    const aliceKeys = generarParClaves();
    const bobKeys = generarParClaves();
    
    console.log('Claves generadas para Alice y Bob');
    
    // Alice envía mensaje a Bob
    const mensajeOriginal = 'Hola Bob, este es un mensaje secreto!';
    const mensajeEnviado = enviarMensaje(mensajeOriginal, bobKeys.publicKey);
    
    console.log('\nMensaje enviado por Alice:');
    console.log('Mensaje cifrado:', mensajeEnviado.mensajeCifrado.substring(0, 50) + '...');
    console.log('Hash:', mensajeEnviado.hash);
    
    // Bob recibe y descifra el mensaje
    const mensajeRecibido = recibirMensaje(mensajeEnviado, bobKeys.privateKey);
    
    console.log('\nMensaje recibido por Bob:');
    console.log('Mensaje:', mensajeRecibido.mensaje);
    console.log('Integridad verificada:', mensajeRecibido.integridadVerificada ? '✅ Sí' : '❌ No');
}

ejemploMensajeria();
```

### Ejemplo 5: Verificación de Integridad de Archivos

```javascript
const cryptoLib = require('./src/index');
const fs = require('fs');

// Crear archivo con hash
async function crearArchivoConHash(contenido, nombreArchivo) {
    fs.writeFileSync(nombreArchivo, contenido);
    const hash = await cryptoLib.hashFile(nombreArchivo, 'sha256');
    
    // Guardar hash en archivo separado
    fs.writeFileSync(nombreArchivo + '.hash', hash);
    
    console.log(`Archivo creado: ${nombreArchivo}`);
    console.log(`Hash guardado: ${hash}`);
    
    return hash;
}

// Verificar integridad de archivo
async function verificarIntegridad(nombreArchivo) {
    try {
        const hashGuardado = fs.readFileSync(nombreArchivo + '.hash', 'utf8');
        const hashActual = await cryptoLib.hashFile(nombreArchivo, 'sha256');
        
        const integridadVerificada = hashGuardado === hashActual;
        
        console.log(`\nVerificación de integridad para ${nombreArchivo}:`);
        console.log('Hash guardado:', hashGuardado);
        console.log('Hash actual:', hashActual);
        console.log('Integridad:', integridadVerificada ? '✅ Archivo íntegro' : '❌ Archivo modificado');
        
        return integridadVerificada;
    } catch (error) {
        console.error('Error al verificar integridad:', error.message);
        return false;
    }
}

// Ejemplo de uso
async function ejemploIntegridad() {
    const contenido = 'Este es un archivo importante que no debe ser modificado.';
    const nombreArchivo = 'archivo-importante.txt';
    
    // Crear archivo con hash
    await crearArchivoConHash(contenido, nombreArchivo);
    
    // Verificar integridad (debería ser válida)
    await verificarIntegridad(nombreArchivo);
    
    // Modificar archivo
    fs.appendFileSync(nombreArchivo, ' - MODIFICADO');
    console.log('\n--- Archivo modificado ---');
    
    // Verificar integridad (debería fallar)
    await verificarIntegridad(nombreArchivo);
    
    // Limpiar archivos
    [nombreArchivo, nombreArchivo + '.hash'].forEach(archivo => {
        if (fs.existsSync(archivo)) fs.unlinkSync(archivo);
    });
}

ejemploIntegridad();
```

### Ejemplo 6: Comparación de Algoritmos de Hash

```javascript
const cryptoLib = require('./src/index');

function compararAlgoritmosHash(texto) {
    console.log(`Comparando algoritmos de hash para: "${texto}"\n`);
    
    const algoritmos = [
        { nombre: 'SHA-256', funcion: cryptoLib.sha256 },
        { nombre: 'MD5', funcion: cryptoLib.md5 },
        { nombre: 'SHA-1', funcion: cryptoLib.sha1 },
        { nombre: 'Keccak-256', funcion: cryptoLib.keccak256 }
    ];
    
    const resultados = {};
    
    algoritmos.forEach(algoritmo => {
        const inicio = Date.now();
        const hash = algoritmo.funcion(texto);
        const tiempo = Date.now() - inicio;
        
        resultados[algoritmo.nombre] = {
            hash: hash,
            longitud: hash.length,
            tiempo: tiempo + 'ms'
        };
        
        console.log(`${algoritmo.nombre}:`);
        console.log(`  Hash: ${hash}`);
        console.log(`  Longitud: ${hash.length} caracteres`);
        console.log(`  Tiempo: ${tiempo}ms\n`);
    });
    
    return resultados;
}

// Ejemplo de uso
const texto = 'Hola mundo criptográfico!';
compararAlgoritmosHash(texto);
```

### Ejemplo 7: Generador de Contraseñas Seguras

```javascript
const cryptoLib = require('./src/index');

function generarContraseñaSegura(longitud = 16, incluirSimbolos = true) {
    const caracteres = {
        minusculas: 'abcdefghijklmnopqrstuvwxyz',
        mayusculas: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        numeros: '0123456789',
        simbolos: '!@#$%^&*()_+-=[]{}|;:,.<>?'
    };
    
    let pool = caracteres.minusculas + caracteres.mayusculas + caracteres.numeros;
    if (incluirSimbolos) {
        pool += caracteres.simbolos;
    }
    
    let contraseña = '';
    for (let i = 0; i < longitud; i++) {
        const randomIndex = Math.floor(Math.random() * pool.length);
        contraseña += pool[randomIndex];
    }
    
    return contraseña;
}

function evaluarSeguridadContraseña(contraseña) {
    const { hash, salt } = cryptoLib.hashPassword(contraseña);
    
    // Simular ataque de fuerza bruta (solo para demostración)
    const inicio = Date.now();
    let intentos = 0;
    const maxIntentos = 100000; // Límite para la demostración
    
    for (let i = 0; i < maxIntentos; i++) {
        const contraseñaPrueba = generarContraseñaSegura(contraseña.length, true);
        const { hash: hashPrueba } = cryptoLib.hashPassword(contraseñaPrueba, salt);
        
        intentos++;
        if (hashPrueba === hash) {
            break;
        }
    }
    
    const tiempo = Date.now() - inicio;
    
    return {
        contraseña: contraseña,
        hash: hash,
        salt: salt,
        intentos: intentos,
        tiempo: tiempo + 'ms',
        segura: intentos >= maxIntentos
    };
}

// Ejemplo de uso
function ejemploContraseñas() {
    console.log('=== Generador de Contraseñas Seguras ===\n');
    
    const contraseñas = [
        generarContraseñaSegura(8, false),   // Contraseña débil
        generarContraseñaSegura(12, true),   // Contraseña media
        generarContraseñaSegura(16, true),   // Contraseña fuerte
        generarContraseñaSegura(20, true)    // Contraseña muy fuerte
    ];
    
    contraseñas.forEach((contraseña, index) => {
        console.log(`Contraseña ${index + 1}: ${contraseña}`);
        const evaluacion = evaluarSeguridadContraseña(contraseña);
        console.log(`Segura: ${evaluacion.segura ? '✅ Sí' : '❌ No'}`);
        console.log(`Intentos probados: ${evaluacion.intentos}`);
        console.log(`Tiempo: ${evaluacion.tiempo}\n`);
    });
}

ejemploContraseñas();
```

### Funciones de Hash

```javascript
const texto = 'Hola mundo';

// SHA-256
const hashSHA256 = cryptoLib.sha256(texto);
console.log(hashSHA256); // a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3

// MD5
const hashMD5 = cryptoLib.md5(texto);
console.log(hashMD5); // 5d41402abc4b2a76b9719d911017c592

// SHA-1
const hashSHA1 = cryptoLib.sha1(texto);
console.log(hashSHA1); // 356a192b7913b04c54574d18c28d46e6395428ab
```

### Cifrado Simétrico (AES)

```javascript
const mensaje = 'Mensaje secreto';
const password = 'miPassword123';

// Cifrado básico
const encrypted = cryptoLib.encryptAES(mensaje, password);
console.log(encrypted.encrypted); // Texto cifrado
console.log(encrypted.iv); // Vector de inicialización

// Descifrado básico
const decrypted = cryptoLib.decryptAES(encrypted.encrypted, password);
console.log(decrypted); // Mensaje secreto

// Cifrado avanzado (recomendado)
const encryptedAdvanced = cryptoLib.encryptAESAdvanced(mensaje, password);
const decryptedAdvanced = cryptoLib.decryptAESAdvanced(encryptedAdvanced, password);
```

### Cifrado Asimétrico (RSA)

```javascript
// Generar par de claves
const keyPair = cryptoLib.generateRSAKeyPair(2048);

// Cifrar con clave pública
const mensaje = 'Mensaje para RSA';
const encrypted = cryptoLib.encryptRSA(mensaje, keyPair.publicKey);

// Descifrar con clave privada
const decrypted = cryptoLib.decryptRSA(encrypted, keyPair.privateKey);
console.log(decrypted); // Mensaje para RSA
```

### Codificación

```javascript
const texto = 'Datos para codificar';

// Base64
const base64 = cryptoLib.encodeBase64(texto);
const decoded = cryptoLib.decodeBase64(base64);

// Hexadecimal
const hex = cryptoLib.encodeHex(texto);
const decodedHex = cryptoLib.decodeHex(hex);
```

### Utilidades

```javascript
// Generar cadena aleatoria
const random = cryptoLib.generateRandomString(32);

// Generar salt
const salt = cryptoLib.generateSalt();

// Hash de contraseña
const password = 'miContraseña123';
const { hash, salt: passwordSalt } = cryptoLib.hashPassword(password);

// Verificar contraseña
const isValid = cryptoLib.verifyPassword(password, hash, passwordSalt);
console.log(isValid); // true
```

## 🎮 Ejecutar Demostraciones

```bash
# Ejecutar la demostración completa
npm start

# Ejecutar ejemplos prácticos
npm run examples

# O directamente con Node
node main.js
node examples/ejemplos-practicos.js
```

## 📁 Estructura del Proyecto

```
├── src/
│   └── index.js          # Librería principal
├── tests/
│   └── crypto.test.js    # Tests unitarios
├── examples/
│   └── ejemplos-practicos.js  # Ejemplos ejecutables
├── web/
│   └── index.html        # Página educativa
├── main.js               # Archivo de demostración
├── package.json          # Configuración del proyecto
├── jest.config.js        # Configuración de Jest
└── README.md             # Documentación
```

## 🔧 API Completa

### Funciones de Hash
- `sha256(text)` - Genera hash SHA-256
- `md5(text)` - Genera hash MD5
- `sha1(text)` - Genera hash SHA-1

### Cifrado Simétrico
- `encryptAES(text, password)` - Cifrado AES básico
- `decryptAES(encryptedText, password)` - Descifrado AES básico
- `encryptAESAdvanced(text, password)` - Cifrado AES avanzado
- `decryptAESAdvanced(encryptedText, password)` - Descifrado AES avanzado

### Cifrado Asimétrico
- `generateRSAKeyPair(keySize)` - Genera par de claves RSA
- `encryptRSA(text, publicKey)` - Cifra con clave pública
- `decryptRSA(encryptedText, privateKey)` - Descifra con clave privada

### Codificación
- `encodeBase64(text)` - Codifica a Base64
- `decodeBase64(base64Text)` - Decodifica desde Base64
- `encodeHex(text)` - Codifica a hexadecimal
- `decodeHex(hexText)` - Decodifica desde hexadecimal

### Utilidades
- `generateRandomString(length)` - Genera cadena aleatoria
- `generateSalt(length)` - Genera salt aleatorio
- `hashPassword(password, salt)` - Hash de contraseña con PBKDF2
- `verifyPassword(password, hash, salt)` - Verifica contraseña

## 🛡️ Consideraciones de Seguridad

- **AES**: Usa AES-256-CBC para cifrado simétrico
- **RSA**: Genera claves de 2048 bits por defecto
- **Hash de contraseñas**: Usa PBKDF2 con 10,000 iteraciones
- **Salt**: Genera salt aleatorio para cada contraseña
- **IV**: Genera vector de inicialización aleatorio para AES

## ⚠️ Advertencias

- MD5 y SHA-1 son vulnerables a ataques de colisión, úsalos solo para casos no críticos
- Para producción, considera usar bibliotecas más robustas como `node-forge` o `libsodium`
- Siempre usa HTTPS en producción para proteger datos en tránsito
- Almacena las claves privadas de forma segura

## 📄 Licencia

MIT License - Ver archivo LICENSE para más detalles.

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📚 Ejemplos Incluidos

La librería incluye ejemplos prácticos ejecutables que demuestran:

1. **Sistema de Autenticación**: Registro y login de usuarios con hash de contraseñas
2. **Cifrado de Documentos**: Cifrado y descifrado de archivos con verificación de integridad
3. **Wallet Ethereum**: Creación de wallets y firma de transacciones
4. **Mensajería Segura**: Comunicación cifrada entre usuarios
5. **Verificación de Integridad**: Detección de modificaciones en archivos
6. **Comparación de Algoritmos**: Análisis de rendimiento de diferentes algoritmos de hash
7. **Generador de Contraseñas**: Creación y evaluación de contraseñas seguras

### Ejecutar Ejemplos

```bash
# Ejecutar todos los ejemplos
npm run examples

# Ver ejemplos específicos en el código
cat examples/ejemplos-practicos.js
```

## 🌐 Página Web Educativa

Incluye una página web completa (`web/index.html`) con:

- **Guía completa de criptografía** para principiantes
- **Explicación de sistemas centralizados vs descentralizados**
- **Conceptos de blockchain y criptomonedas**
- **Mejores prácticas de seguridad**
- **Diseño moderno y responsive**

Para ver la página web, abre `web/index.html` en tu navegador.

## 📞 Contacto

Creado por Luis - [@tu-usuario](https://github.com/tu-usuario)

---

⭐ ¡Si te gusta este proyecto, dale una estrella! ⭐
