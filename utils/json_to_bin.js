import {argv,exit} from 'node:process';


if(argv.length < 4){
	exit;
}

let json = JSON.parse(argv[2]);

if(!'bytes' in json){
	exit;
}

let arrBuff = new Uint8Array(json['bytes']);

console.log(arrBuff)
