'use strict';
import crypto = require('crypto');
import { isConstructorDeclaration } from 'typescript';
import { PublicKey } from '../rsa/publicKey';
const bc = require('bigint-conversion');
import { RSA  as classRSA} from "../rsa/rsa";
import * as objectSha from 'object-sha'

let rsa  = new classRSA;
let keyPair;
execrsa()   //ejecuta el generateRandomKeys() al iniciarse el program para tener las claves para todo el rato
let pubKeyClientnon;  //necesito la clave pub del cliente de non repudiation
let Pkp;
let bodysendserver;



///////////////////////////////NON-REPUDIATION/////////////////////////////

async function execrsa(){   //genera las keyPair //sigo necesitando mis claves pub y priv
  keyPair= await rsa.generateRandomKeys();
  console.log("ok")
}

async function postNonRepudiation(req, res) {   //tendre que hacer el digitalSignature y el verifyProof
  try {
    let receptionbody = req.body.body;
    let proof = bc.hexToBigint(req.body.proof.proof);
    let ver = await VerifyProof(proof, receptionbody)
    if (ver=="verify"){
      console.log("de puting madre")
      let date = new Date()
      const unixtime = date.valueOf()
      bodysendserver = {type: "4", src: receptionbody.src, dst: receptionbody.dst, ttp: receptionbody.ttp, ts: unixtime, msg: receptionbody.msg}
      let bodysendclient = {type: "4", src: receptionbody.src, dst: receptionbody.dst, ttp: receptionbody.ttp, ts: unixtime}  //sin el mensaje
      Pkp = await digitalSignature(bodysendserver)  // ¿preguntar si se hace el Pkp con el del mensaje como vemos en el pdf?
      let objclient: Object = {
        body: bodysendclient,
        proof: {type: "publication", proof: Pkp, fields:["type", "src", "dst", "ttp", "ts"]}, 

      }
      return res.status(200).send({obj: objclient})
    }
    else console.log("proof: " + proof + "reception body: " + receptionbody)
    res.status(501).send({message: "va algo mal"})
  }
  catch(err) {
    console.log(err)
    res.status(500).send ({ message: err})
  }
}


async function getObjectServer(req, res) {    //lo necesito porque le debo pasar al cliente mi PubKey (en el paso 3)

  try {
 
    bodysendserver.type="5"
    //keyPair = await rsa.generateRandomKeys(); //NO PONER this.
    Pkp = await digitalSignature(bodysendserver)
    let objserver: Object = {
      body: bodysendserver,
      proof: {type: "publication", proof: Pkp, fields:["type", "src", "dst", "ttp", "ts", "msg"]},
    }
    console.log(objserver)
    return res.status(200).send({
      object: objserver,
    })
  }
  catch(err) {
    console.log("error recibiendo publication "+ err)
    res.status(500).send ({ message: err})   
  }
}



async function getPublicKeyNonRepudiation(req, res) {    //lo necesito porque le debo pasar al serever (B) mi PubKey (en el paso 5)

        try {
          //keyPair = await rsa.generateRandomKeys(); //NO PONER this.
          
          res.status(200).send({
            e: await bc.bigintToHex(rsa.publicKey.e),
            n: await bc.bigintToHex(rsa.publicKey.n)
          })
        }
        catch(err) {
          console.log("error recibiendo la public key"+ err)
          res.status(500).send ({ message: err})   
        }
  }

async function postpubKeyNonRepudiation(req, res) {   //el cliente me pasa su pubKey para validar la prueba Pko
  try {
    let e = req.body.e;
    let n = req.body.n;
    e = bc.hexToBigint(e)
    n =  await bc.hexToBigint(n)
    console.log("TTP, esto es la e:" + e)
    console.log("TTP, esto es la n:" + n)
    pubKeyClientnon = new PublicKey (e, n)  //creo una nueva publicKey del cliente 
    console.log("ha llegado pub key: "+ pubKeyClientnon)
    return res.status(200).send({message: "La TTP ya tiene tu publicKey"})
  }
  catch(err) {
    res.status(500).send ({ message: err})
  }
}

      
async function signMsgRSA(req, res) {
    try {
      const m = bc.hexToBigint(req.body.msg);
      const s = await keyPair["privateKey"].sign(m);
      res.status(200).send({msg: bc.bigintToHex(s)})
    }
    catch(err) {
      res.status(500).send ({ message: err})
    }
  }

async function getFraseRSA(req, res) {
  let msgg= "Prueba"
  console.log(pubKeyClientnon.n)
  let encmsg= await pubKeyClientnon.encrypt(msgg)
    try {
      res.status(200).send({msg: encmsg})
    } 
    catch (err) {
      console.log(err)
      res.status(500).send({msg: err})
    }
  }

  async function digitalSignature(obj:Object){
    const digest = await objectSha.digest(obj)
    const test = await bc.bigintToHex(rsa.privateKey.sign(bc.hexToBigint(digest))); //si no va cambiar a hex
  
    return test; //si no va cambiar a hex
  }

  async function VerifyProof(proof:Object, body:Object)  //verifica con la pubKey de A (cliente)
  {
    const hashobj= await objectSha.digest(body)
    const hashproof= await bc.bigintToText(pubKeyClientnon.verify(proof))
    console.log("1: "+hashobj)
    console.log("2: "+ hashproof)
    console.log(hashobj==hashproof)
    if (hashobj==hashproof){
      return "verify"
    }
    else 
    {
      return "noverify"
    }
  }
  
module.exports = {postNonRepudiation, getPublicKeyNonRepudiation, postpubKeyNonRepudiation, signMsgRSA, getObjectServer};



