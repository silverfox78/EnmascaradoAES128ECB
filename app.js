'use strict';

import { createCipheriv, createDecipheriv } from 'crypto';
import jwt from 'jsonwebtoken';

const seguridad = {
    TokenFirma: 'O6YCiychJtvStXPp', // https://www.avast.com/es-ww/random-password-generator
    TokenExpira: 3000,
    LlaveOfuscado: 'F9fWH1U23IYyFSYc', //Llave de 16 caracteres - https://www.avast.com/es-ww/random-password-generator
    Usuario: 'Liberty',
    Clave: 'ClaveAsignadaALiberty',
    Algoritmo: 'aes-128-ecb',
    EncodingInicial: 'base64',
    EncodingFinal: 'utf8'
}

function obtieneKey () {
    return seguridad.LlaveOfuscado
}

function obtieneUsuario () {
    return seguridad.Usuario
}

function obtieneClave () {
    return seguridad.Clave
}

function enmascara(texto) {
    const cipher = createCipheriv(seguridad.Algoritmo, obtieneKey(), null);
    return Buffer.concat([cipher.update(texto), cipher.final()]).toString(seguridad.EncodingInicial);
}

function desenmascara(texto) {
    const cipher = createDecipheriv(seguridad.Algoritmo, obtieneKey(), null);
    let textoEnmascarado = Buffer.from(texto, seguridad.EncodingInicial);
    return Buffer.concat([cipher.update(textoEnmascarado), cipher.final()]).toString(seguridad.EncodingFinal);
}

function generaDatos(fecha){
    return {
        Usuario: obtieneUsuario(),
        Clave: obtieneClave(),
        Fecha: fecha
    } 
}

function generaTextoOfuscado(datos){
    let informacion = JSON.stringify(datos);
    return enmascara(informacion);
}

function generaPayload (fecha, textoOfuscado){
    return {
        Usuario: obtieneUsuario(),
        Informacion: textoOfuscado,
        Fecha: fecha
    }
}

let utcEnviar = new Date().getTime();
let datosOriginales = generaDatos(utcEnviar);
console.log('Informacion original: ', datosOriginales);

let textoOfuscado = generaTextoOfuscado(datosOriginales);
console.log('Informacion ofuscada: ', textoOfuscado);

let payload = generaPayload(utcEnviar, textoOfuscado);
console.log('Payload a enviar: ', payload);

const token = 
    jwt.sign(
        payload, 
        seguridad.TokenFirma, 
        {
            expiresIn: seguridad.TokenExpira
        }
    );

console.log('Token generado: ', token);

let decoded = jwt.decode(token, seguridad.TokenFirma);
console.log('Token informacion: ', decoded);

let desofuscado = JSON.parse(desenmascara(decoded.Informacion));
console.log('Texto desenmascarado: ', desofuscado);

console.log('Usuario desenmascarado: ', desofuscado.Usuario);
console.log('Clave desenmascarado: ', desofuscado.Clave);
