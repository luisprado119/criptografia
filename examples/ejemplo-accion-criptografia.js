/**
 * EJEMPLO: Sistema de Acciones con Criptografía Automática
 * Este ejemplo muestra cómo generar criptografía automáticamente según el tipo de acción
 */

const cryptoLib = require('../src/index');

console.log('🎯 EJEMPLO: ACCIONES CON CRIPTOGRAFÍA AUTOMÁTICA 🎯\n');

// ==================== SISTEMA DE ACCIONES CRIPTOGRÁFICAS ====================

class SistemaAccionesCriptograficas {
    constructor() {
        this.acciones = new Map();
        this.configuracion = {
            // Configuración por tipo de acción
            'hash': {
                algoritmo: 'sha256',
                descripcion: 'Generar hash de datos'
            },
            'cifrado': {
                algoritmo: 'aes',
                descripcion: 'Cifrar datos sensibles'
            },
            'firma': {
                algoritmo: 'secp256k1',
                descripcion: 'Firmar documentos digitalmente'
            },
            'ethereum': {
                algoritmo: 'ethereum',
                descripcion: 'Operaciones con Ethereum'
            },
            'archivo': {
                algoritmo: 'aes',
                descripcion: 'Cifrar archivos'
            }
        };
    }

    // Registrar una acción
    registrarAccion(id, tipo, datos, parametros = {}) {
        const accion = {
            id,
            tipo,
            datos,
            parametros,
            timestamp: new Date(),
            estado: 'pendiente',
            resultado: null
        };

        this.acciones.set(id, accion);
        console.log(`📝 Acción registrada: ${id} (${tipo})`);
        return accion;
    }

    // Ejecutar acción con criptografía automática
    async ejecutarAccion(id) {
        const accion = this.acciones.get(id);
        if (!accion) {
            throw new Error(`Acción ${id} no encontrada`);
        }

        console.log(`\n🚀 Ejecutando acción: ${id}`);
        console.log(`   Tipo: ${accion.tipo}`);
        console.log(`   Descripción: ${this.configuracion[accion.tipo]?.descripcion || 'Sin descripción'}`);

        try {
            let resultado;

            switch (accion.tipo) {
                case 'hash':
                    resultado = await this.ejecutarHash(accion);
                    break;
                case 'cifrado':
                    resultado = await this.ejecutarCifrado(accion);
                    break;
                case 'firma':
                    resultado = await this.ejecutarFirma(accion);
                    break;
                case 'ethereum':
                    resultado = await this.ejecutarEthereum(accion);
                    break;
                case 'archivo':
                    resultado = await this.ejecutarArchivo(accion);
                    break;
                default:
                    throw new Error(`Tipo de acción no soportado: ${accion.tipo}`);
            }

            accion.estado = 'completada';
            accion.resultado = resultado;
            accion.fechaCompletada = new Date();

            console.log(`✅ Acción ${id} completada exitosamente`);
            return resultado;

        } catch (error) {
            accion.estado = 'error';
            accion.error = error.message;
            console.error(`❌ Error en acción ${id}: ${error.message}`);
            throw error;
        }
    }

    // Ejecutar acción de hash
    async ejecutarHash(accion) {
        const { datos, parametros } = accion;
        const algoritmo = parametros.algoritmo || 'sha256';

        console.log(`   🔍 Generando hash ${algoritmo.toUpperCase()}`);

        let hash;
        if (typeof datos === 'string') {
            // Hash de texto
            switch (algoritmo) {
                case 'sha256':
                    hash = cryptoLib.sha256(datos);
                    break;
                case 'md5':
                    hash = cryptoLib.md5(datos);
                    break;
                case 'sha1':
                    hash = cryptoLib.sha1(datos);
                    break;
                case 'keccak256':
                    hash = cryptoLib.keccak256(datos);
                    break;
                default:
                    throw new Error(`Algoritmo de hash no soportado: ${algoritmo}`);
            }
        } else {
            // Hash de archivo
            hash = await cryptoLib.hashFile(datos, algoritmo);
        }

        const resultado = {
            tipo: 'hash',
            algoritmo,
            hash,
            longitud: hash.length,
            timestamp: new Date()
        };

        console.log(`   📊 Hash generado: ${hash.substring(0, 20)}...`);
        return resultado;
    }

    // Ejecutar acción de cifrado
    async ejecutarCifrado(accion) {
        const { datos, parametros } = accion;
        const password = parametros.password || 'defaultPassword123';
        const algoritmo = parametros.algoritmo || 'aes';

        console.log(`   🔐 Cifrando datos con ${algoritmo.toUpperCase()}`);

        let resultado;
        if (algoritmo === 'aes') {
            const cifrado = cryptoLib.encryptAESAdvanced(datos, password);
            const hashOriginal = cryptoLib.sha256(datos);

            resultado = {
                tipo: 'cifrado',
                algoritmo: 'aes',
                datosCifrados: cifrado,
                hashOriginal,
                password: password.substring(0, 5) + '...', // Solo mostrar parte de la password
                timestamp: new Date()
            };
        } else if (algoritmo === 'rsa') {
            const keyPair = cryptoLib.generateRSAKeyPair();
            const cifrado = cryptoLib.encryptRSA(datos, keyPair.publicKey);

            resultado = {
                tipo: 'cifrado',
                algoritmo: 'rsa',
                datosCifrados: cifrado,
                publicKey: keyPair.publicKey.substring(0, 50) + '...',
                privateKey: keyPair.privateKey.substring(0, 50) + '...',
                timestamp: new Date()
            };
        } else {
            throw new Error(`Algoritmo de cifrado no soportado: ${algoritmo}`);
        }

        console.log(`   📦 Datos cifrados exitosamente`);
        return resultado;
    }

    // Ejecutar acción de firma
    async ejecutarFirma(accion) {
        const { datos, parametros } = accion;
        const tipoFirma = parametros.tipo || 'secp256k1';

        console.log(`   ✍️ Firmando con ${tipoFirma.toUpperCase()}`);

        let resultado;
        if (tipoFirma === 'secp256k1') {
            const keyPair = cryptoLib.generateSecp256k1KeyPair();
            const signature = cryptoLib.signSecp256k1(datos, keyPair.privateKey);

            resultado = {
                tipo: 'firma',
                algoritmo: 'secp256k1',
                mensaje: datos,
                firma: signature.signature,
                publicKey: keyPair.publicKey,
                privateKey: keyPair.privateKey,
                recoveryId: signature.recoveryId,
                timestamp: new Date()
            };
        } else if (tipoFirma === 'secp256r1') {
            const keyPair = cryptoLib.generateSecp256r1KeyPair();
            const signature = cryptoLib.signSecp256r1(datos, keyPair.privateKey);

            resultado = {
                tipo: 'firma',
                algoritmo: 'secp256r1',
                mensaje: datos,
                firma: signature.signature,
                publicKey: keyPair.publicKey,
                privateKey: keyPair.privateKey,
                r: signature.r,
                s: signature.s,
                timestamp: new Date()
            };
        } else {
            throw new Error(`Tipo de firma no soportado: ${tipoFirma}`);
        }

        console.log(`   📝 Documento firmado exitosamente`);
        return resultado;
    }

    // Ejecutar acción de Ethereum
    async ejecutarEthereum(accion) {
        const { datos, parametros } = accion;
        const tipoOperacion = parametros.operacion || 'wallet';

        console.log(`   🚀 Ejecutando operación Ethereum: ${tipoOperacion}`);

        let resultado;
        if (tipoOperacion === 'wallet') {
            const keyPair = cryptoLib.generateSecp256k1KeyPair();
            const address = cryptoLib.getEthereumAddress(keyPair.publicKey);

            resultado = {
                tipo: 'ethereum',
                operacion: 'wallet',
                address,
                publicKey: keyPair.publicKey,
                privateKey: keyPair.privateKey,
                timestamp: new Date()
            };
        } else if (tipoOperacion === 'transaccion') {
            const keyPair = cryptoLib.generateSecp256k1KeyPair();
            const address = cryptoLib.getEthereumAddress(keyPair.publicKey);

            const transaccion = {
                from: address,
                to: parametros.to || '0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6',
                value: parametros.value || '1000000000000000000',
                gas: '21000',
                gasPrice: '20000000000',
                nonce: 0
            };

            const transaccionString = JSON.stringify(transaccion);
            const hashTransaccion = cryptoLib.keccak256(transaccionString);
            const signature = cryptoLib.signSecp256k1(hashTransaccion, keyPair.privateKey);

            resultado = {
                tipo: 'ethereum',
                operacion: 'transaccion',
                transaccion,
                hash: hashTransaccion,
                firma: signature.signature,
                recoveryId: signature.recoveryId,
                timestamp: new Date()
            };
        } else if (tipoOperacion === 'mensaje') {
            const keyPair = cryptoLib.generateSecp256k1KeyPair();
            const address = cryptoLib.getEthereumAddress(keyPair.publicKey);
            const signature = cryptoLib.signEthereumMessage(datos, keyPair.privateKey);

            resultado = {
                tipo: 'ethereum',
                operacion: 'mensaje',
                mensaje: datos,
                address,
                firma: signature.signature,
                recoveryId: signature.recoveryId,
                timestamp: new Date()
            };
        } else {
            throw new Error(`Operación Ethereum no soportada: ${tipoOperacion}`);
        }

        console.log(`   ⛓️ Operación Ethereum completada`);
        return resultado;
    }

    // Ejecutar acción de archivo
    async ejecutarArchivo(accion) {
        const { datos, parametros } = accion;
        const operacion = parametros.operacion || 'cifrar';
        const password = parametros.password || 'defaultPassword123';

        console.log(`   📁 Operación de archivo: ${operacion}`);

        let resultado;
        if (operacion === 'cifrar') {
            // Crear archivo temporal
            const fs = require('fs');
            const archivoOriginal = `temp_${Date.now()}.txt`;
            const archivoCifrado = `temp_${Date.now()}_encrypted.enc`;

            fs.writeFileSync(archivoOriginal, datos);

            const encryptResult = await cryptoLib.encryptFile(archivoOriginal, archivoCifrado, password);
            const hashOriginal = await cryptoLib.hashFile(archivoOriginal, 'sha256');

            // Limpiar archivos temporales
            fs.unlinkSync(archivoOriginal);
            fs.unlinkSync(archivoCifrado);

            resultado = {
                tipo: 'archivo',
                operacion: 'cifrar',
                archivoCifrado: 'Archivo cifrado exitosamente',
                hashOriginal,
                iv: encryptResult.iv,
                timestamp: new Date()
            };
        } else if (operacion === 'hash') {
            // Crear archivo temporal
            const fs = require('fs');
            const archivoTemporal = `temp_${Date.now()}.txt`;
            fs.writeFileSync(archivoTemporal, datos);

            const hash = await cryptoLib.hashFile(archivoTemporal, 'sha256');
            fs.unlinkSync(archivoTemporal);

            resultado = {
                tipo: 'archivo',
                operacion: 'hash',
                hash,
                algoritmo: 'sha256',
                timestamp: new Date()
            };
        } else {
            throw new Error(`Operación de archivo no soportada: ${operacion}`);
        }

        console.log(`   📄 Operación de archivo completada`);
        return resultado;
    }

    // Listar todas las acciones
    listarAcciones() {
        console.log('\n📋 ACCIONES REGISTRADAS:');
        console.log('='.repeat(50));

        this.acciones.forEach((accion, id) => {
            console.log(`ID: ${id}`);
            console.log(`   Tipo: ${accion.tipo}`);
            console.log(`   Estado: ${accion.estado}`);
            console.log(`   Fecha: ${accion.timestamp.toLocaleString()}`);
            if (accion.estado === 'completada') {
                console.log(`   ✅ Completada: ${accion.fechaCompletada.toLocaleString()}`);
            } else if (accion.estado === 'error') {
                console.log(`   ❌ Error: ${accion.error}`);
            }
            console.log();
        });
    }

    // Obtener estadísticas
    obtenerEstadisticas() {
        const total = this.acciones.size;
        const completadas = Array.from(this.acciones.values()).filter(a => a.estado === 'completada').length;
        const errores = Array.from(this.acciones.values()).filter(a => a.estado === 'error').length;
        const pendientes = Array.from(this.acciones.values()).filter(a => a.estado === 'pendiente').length;

        const estadisticas = {
            total,
            completadas,
            errores,
            pendientes,
            tasaExito: total > 0 ? (completadas / total * 100).toFixed(2) + '%' : '0%'
        };

        console.log('\n📊 ESTADÍSTICAS:');
        console.log('='.repeat(30));
        console.log(`Total de acciones: ${estadisticas.total}`);
        console.log(`Completadas: ${estadisticas.completadas}`);
        console.log(`Errores: ${estadisticas.errores}`);
        console.log(`Pendientes: ${estadisticas.pendientes}`);
        console.log(`Tasa de éxito: ${estadisticas.tasaExito}`);

        return estadisticas;
    }
}

// ==================== EJEMPLOS DE USO ====================

async function ejemplosAcciones() {
    const sistema = new SistemaAccionesCriptograficas();

    try {
        console.log('🎯 REGISTRANDO ACCIONES...\n');

        // 1. Acción de hash
        sistema.registrarAccion('hash1', 'hash', 'Hola mundo criptográfico!', { algoritmo: 'sha256' });
        sistema.registrarAccion('hash2', 'hash', 'Datos importantes', { algoritmo: 'keccak256' });

        // 2. Acción de cifrado
        sistema.registrarAccion('cifrado1', 'cifrado', 'Información confidencial', {
            algoritmo: 'aes',
            password: 'miPassword123'
        });
        sistema.registrarAccion('cifrado2', 'cifrado', 'Datos sensibles', {
            algoritmo: 'rsa'
        });

        // 3. Acción de firma
        sistema.registrarAccion('firma1', 'firma', 'Contrato importante', { tipo: 'secp256k1' });
        sistema.registrarAccion('firma2', 'firma', 'Documento legal', { tipo: 'secp256r1' });

        // 4. Acción de Ethereum
        sistema.registrarAccion('eth1', 'ethereum', null, { operacion: 'wallet' });
        sistema.registrarAccion('eth2', 'ethereum', null, {
            operacion: 'transaccion',
            to: '0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6',
            value: '2000000000000000000'
        });
        sistema.registrarAccion('eth3', 'ethereum', 'Mensaje para firmar', { operacion: 'mensaje' });

        // 5. Acción de archivo
        sistema.registrarAccion('archivo1', 'archivo', 'Contenido del archivo importante', {
            operacion: 'cifrar',
            password: 'archivoPassword123'
        });
        sistema.registrarAccion('archivo2', 'archivo', 'Datos del archivo', { operacion: 'hash' });

        console.log('\n🚀 EJECUTANDO ACCIONES...\n');

        // Ejecutar todas las acciones
        const accionesIds = Array.from(sistema.acciones.keys());

        for (const id of accionesIds) {
            try {
                const resultado = await sistema.ejecutarAccion(id);
                console.log(`   📋 Resultado de ${id}:`, {
                    tipo: resultado.tipo,
                    algoritmo: resultado.algoritmo || resultado.operacion,
                    timestamp: resultado.timestamp
                });
            } catch (error) {
                console.error(`   ❌ Error en ${id}: ${error.message}`);
            }
        }

        // Mostrar estadísticas
        sistema.obtenerEstadisticas();

        // Listar todas las acciones
        sistema.listarAcciones();

    } catch (error) {
        console.error('❌ Error general:', error.message);
    }
}

// ==================== EJEMPLO DE ACCIÓN ESPECÍFICA ====================

async function ejemploAccionEspecifica() {
    console.log('\n🎯 EJEMPLO DE ACCIÓN ESPECÍFICA');
    console.log('='.repeat(50));

    const sistema = new SistemaAccionesCriptograficas();

    // Crear una acción específica para cifrar un documento
    const documento = `
    CONTRATO DE CONFIDENCIALIDAD
    
    Este documento contiene información confidencial y propietaria.
    Fecha: ${new Date().toLocaleDateString()}
    Cliente: Empresa ABC
    Valor: $100,000 USD
    
    Términos y condiciones:
    1. Información confidencial
    2. No divulgación
    3. Uso restringido
    `;

    // Registrar acción de cifrado específica
    const accion = sistema.registrarAccion('contrato_confidencial', 'cifrado', documento, {
        algoritmo: 'aes',
        password: 'contrato2024!'
    });

    console.log(`📄 Documento a cifrar: ${documento.length} caracteres`);

    // Ejecutar la acción
    const resultado = await sistema.ejecutarAccion('contrato_confidencial');

    console.log('\n📊 RESULTADO DE LA ACCIÓN:');
    console.log(`   Tipo: ${resultado.tipo}`);
    console.log(`   Algoritmo: ${resultado.algoritmo}`);
    console.log(`   Hash original: ${resultado.hashOriginal}`);
    console.log(`   Datos cifrados: ${resultado.datosCifrados.substring(0, 50)}...`);
    console.log(`   Timestamp: ${resultado.timestamp}`);

    // Ahora descifrar para verificar
    console.log('\n🔓 VERIFICANDO CIFRADO...');
    try {
        const datosDescifrados = cryptoLib.decryptAESAdvanced(resultado.datosCifrados, 'contrato2024!');
        const hashVerificado = cryptoLib.sha256(datosDescifrados);
        const integridadVerificada = hashVerificado === resultado.hashOriginal;

        console.log(`   ✅ Descifrado exitoso`);
        console.log(`   ✅ Integridad verificada: ${integridadVerificada ? 'Sí' : 'No'}`);
        console.log(`   📄 Contenido descifrado: ${datosDescifrados.substring(0, 100)}...`);
    } catch (error) {
        console.error(`   ❌ Error al descifrar: ${error.message}`);
    }
}

// ==================== EJECUTAR EJEMPLOS ====================

async function ejecutarEjemplos() {
    await ejemplosAcciones();
    await ejemploAccionEspecifica();

    console.log('\n🎉 ¡Todos los ejemplos de acciones con criptografía ejecutados exitosamente! 🎉');
}

// Ejecutar ejemplos
ejecutarEjemplos();
