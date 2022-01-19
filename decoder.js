// ワクチン接種証明書のQRコードをデコードし、内容を表示、ベリファイするJavaScript
// 
// adapted from
// https://github.com/dvci/health-cards-walkthrough/blob/main/SMART%20Health%20Cards.ipynb 
//
// 前提ソフトウェア：
//   Node.js
//
// 起動方法：
//   node deocder.js <画像ファイルのパス>
//
// あらかじめ必要なパッケージをインストールしておく
//   npm install jsqr
//   npm install pngjs
//   npm install zlib
//   npm install node-jose
//   npm install sync-request
//
const fs = require('fs');
const jsQR = require('jsqr');
const PNG = require('pngjs').PNG;
const zlib = require('zlib');
const jose = require('node-jose');
const request = require('sync-request');

// ワクチン接種証明書のQRコード画像ファイル
let imagePath = './smart-health-card.png';
if (process.argv.length >= 2)
    imagePath = process.argv[2];

decode(imagePath);

async function decode(imagePath){
	console.log("1. QR画像ファイルを読み込んでいます..." + imagePath);
	const imageFile = fs.readFileSync(imagePath);
	const image = PNG.sync.read(imageFile);
	const imageData = new Uint8ClampedArray(image.data.buffer);

	console.log("");
	console.log("2. QRを解析しています...");
	const scannedQR = jsQR(imageData, image.width, image.height); 
	console.log("   QRコード==>" + scannedQR.data);

	console.log("");
	console.log("3. Base64をデコードしています...");
	const scannedJWS = scannedQR
		  .data
		  .match(/(\d\d?)/g)
		  .map(num => String.fromCharCode(parseInt(num, 10) + 45)).join('');
	console.log("      JWS==> " + scannedJWS);

	console.log("");
	console.log("4. JWSを3成分に分解しています...");
	const [ header, payload, signature ] = scannedJWS.split('.');

	console.log("   HEADER==> " + header);
	console.log("  PAYLOAD==> " + payload);
	console.log("SIGNATURE==> " + signature);

	console.log("");
	console.log("5. ペイロードをデコードし、ZIP展開しています...");
	const decodedPayload = Buffer.from(payload, 'base64');
	const decompressedCard = zlib.inflateRawSync(decodedPayload);
	const card = JSON.parse(decompressedCard.toString());
	const issuer = card.iss;
	console.log("     CARD==> " + JSON.stringify(card));
	console.log("   ISSUER==> " + issuer);

	console.log("");
	console.log("6. 発行者の公開キーをダウンロードしています...");
	const result = request('GET', `${issuer}/.well-known/jwks.json`);
	const data = JSON.parse(result.body.toString());
	console.log("     JWKS==> " + JSON.stringify(data));

	console.log("");
	console.log("7. 電子署名を検証しています...");
	const keystore = await asKeyStore(data.keys);
	const verifiedCARD = await verify(keystore, scannedJWS);
	const verifyResult = JSON.stringify(verifiedCARD) === JSON.stringify(card);
	console.log(" VERIFIED==> " + verifyResult);

	console.log("");
	console.log("8. Bundleリソースを抽出しています...");
	const fhirBundle = card.vc.credentialSubject.fhirBundle;
	console.log("   Bundle==> " + JSON.stringify(fhirBundle, null, "  "));

	const patient = fhirBundle.entry[0].resource;
	const name = 
		  patient.name[0].family + " " +
		  patient.name[0].given.join(" ");

	console.log("");
	console.log("ワクチン接種情報---");
	console.log("   対象者名==> " + name);
	console.log("   生年月日==> " + patient.birthDate);

	for ( n=1; n<fhirBundle.entry.length; n++){
		let resource = fhirBundle.entry[n].resource;
		console.log(n + "回目の接種:");
		console.log("   　接種日==> " + resource.occurrenceDateTime);
		console.log(" 　ワクチン==> " + resource.vaccineCode.coding[0].code
				   + " (" + resource.vaccineCode.coding[0].system + ")");
		console.log(" ロット番号==> " + resource.lotNumber);
	}
}

async function asKeyStore(result) {
   return await jose.JWK.asKeyStore(result);
}

async function verify(keystore, scannedJWS) {
   const verified = await jose.JWS.createVerify(keystore).verify(scannedJWS);
   const raw = await zlib.inflateRawSync(verified.payload);
   return JSON.parse(raw.toString('utf8'));
}
