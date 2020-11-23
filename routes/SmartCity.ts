"use strict";

import express = require("express");
let router = express.Router();
let casoControl = require('../controllers/casoControl');



///////////////////////////////NON-REPUDIATION/////////////////////////////
router.post('/sign', casoControl.signMsgRSA);
//router.get('/getFraseRSA', casoControl.getFraseRSA);
router.get('/publickey', casoControl.getPublicKeyNonRepudiation);    // B y A necesitas validar Pkp por tanto necesita pubKey de TTP
router.post('/postTTP', casoControl.postNonRepudiation); 
router.get('/getTTPobj', casoControl.getObjectServer);   
router.post('/postpublicKey', casoControl.postpubKeyNonRepudiation);  // TTP necesita la publica de A para validar la Pko

// A necesitara validar la Pkp


module.exports = router;