"use strict";
//¡¡¡¡¡¡¡¡¡IMPORTANTE: EL NOMBRE DE LAS COLECCIONES EN MINUSCULA PORQUE SINO NO LAS DETECTA!!!!!!!!!
//Import libraries
import express = require("express");
import cors = require("cors");
import bodyParser = require('body-parser');




let smartCity = require("./routes/SmartCity");


//Server variable initialization
let app = express();
app.use(express.json());
app.use(cors());
app.use(bodyParser.json()); 
//app.use(bodyParser.json({ type: 'application/*+json' })); //para poder enviar json con el POST



app.use('/caso', smartCity);   





//Make app listen on port 3000
const port = 7800; // en el puerto que vamos a escuchar
app.listen(port, function () {
    console.log('Listening on http://localhost:' + port);
});
module.exports = app;
