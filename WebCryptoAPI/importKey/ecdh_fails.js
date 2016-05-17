//
//
//


var ecPublicKey = new Uint8Array([6, 7, 42, 134, 72, 206, 61, 2, 1]);

var curveP256 = new Uint8Array([6, 8, 42, 134, 72, 206, 61, 3, 1, 7]);
var curveP384 = new Uint8Array([6, 5, 0x2b, 0x81, 4, 0, 0x22]); 
var curveP521 = new Uint8Array([6, 5, 0x2b, 0x81, 4, 0, 0x23]); 
var curveUnknown = new Uint8Array([6, 5, 0x2b, 0x81, 4, 1, 0x23]); 


var p256Key = {
    crv: "P-256",
    x: new Uint8Array([80, 47, 166, 102, 158, 117, 129, 203, 218, 83, 96, 135, 203, 221, 77, 78, 188, 252, 80, 209, 133, 224, 94, 138, 207, 116, 156, 218, 217, 248, 43, 104]),
    y: new Uint8Array([79, 30, 231, 171, 214, 163, 172, 237, 113, 167, 159, 232, 173, 232, 24, 159, 15, 250, 152, 79, 67, 87, 66, 205, 123, 172, 108, 81, 180, 24, 225, 135]),
    d: new Uint8Array([46, 83, 140, 27, 252, 231, 165, 83, 198, 243, 207, 60, 213, 105, 64, 147, 204, 176, 44, 146, 60, 79, 161, 206, 151, 237, 71, 189, 244, 179, 174, 114])
};

var p384Key = {
    crv: "P-384",
    x: new Uint8Array([198, 202, 0, 243, 32, 245, 144, 206, 195, 190, 92, 67, 83, 164, 107, 1, 215, 250, 9, 128, 124, 61, 100, 239, 163, 67, 228, 107, 33, 240, 123, 129, 29, 225, 79, 185, 215, 66, 139, 231, 43, 155, 0, 84, 188, 75, 35, 7]),
    y: new Uint8Array([138, 80, 220, 30, 119, 10, 95, 240, 42, 46, 60, 242, 43, 186, 145, 41, 163, 26, 51, 183, 166, 66, 116, 215, 172, 200, 184, 61, 137, 98, 73, 58, 11, 228, 173, 195, 15, 13, 117, 236, 4, 213, 253, 186, 34, 50, 140, 127]),
    d: new Uint8Array([114, 93, 89, 53, 184, 206, 14, 85, 233, 65, 174, 28, 13, 189, 32, 153, 187, 238, 253, 218, 129, 239, 209, 1, 62, 48, 22, 97, 107, 174, 46, 63, 38, 106, 124, 34, 234, 103, 92, 127, 92, 139, 226, 216, 151, 82, 234, 255])
};

var p521Key = {
    crv: "P-521",
    x: new Uint8Array([1, 146, 173, 116, 156, 46, 131, 203, 201, 141, 27, 21, 45, 216, 233, 150, 242, 49, 12, 105, 31, 251, 121, 83, 59, 78, 243, 17, 82, 94, 158, 138, 34, 29, 103, 224, 80, 211, 110, 172, 173, 229, 184, 128, 75, 142, 42, 3, 192, 167, 176, 7, 114, 165, 27, 247, 94, 148, 117, 101, 137, 191, 73, 175, 141, 248]),
    y: new Uint8Array([1, 201, 33, 2, 251, 2, 37, 229, 49, 108, 18, 187, 174, 37, 158, 18, 127, 143, 38, 175, 186, 86, 22, 71, 189, 158, 139, 117, 24, 11, 248, 201, 145, 10, 199, 14, 33, 31, 194, 190, 20, 77, 155, 59, 204, 21, 229, 122, 231, 183, 50, 62, 207, 45, 186, 244, 194, 201, 130, 105, 43, 180, 99, 88, 205, 160]),
    d: new Uint8Array([1, 115, 217, 106, 104, 247, 216, 5, 5, 66, 132, 87, 70, 65, 50, 39, 174, 129, 103, 160, 245, 180, 4, 188, 68, 144, 199, 168, 23, 91, 233, 54, 20, 183, 204, 115, 134, 90, 172, 75, 40, 120, 76, 145, 108, 115, 34, 48, 11, 58, 153, 228, 4, 194, 82, 147, 86, 43, 173, 12, 16, 190, 46, 211, 172, 86])
};

function toBase64(data)
{
    if (data[0] == 0) {
        data = data.subarray(1);
    }
    return base64js.fromByteArrayURL(data);
}

function extend(data)
{
    var x = base64js.toByteArrayURL(data);
    vary = asn1_to_uint8([data, new Uint8Array([0])]);
    return toBase64(y);
}
    

function shorten(data)
{
    var x = base64js.toByteArrayURL(data);
    return toBase64(new Uint8Array(x.buffer, 1, x.length-1));
}

function shortenBinary(data)
{
    return new Uint8Array(data.buffer, 1, data.length-1);
}

function extendBinary(data)
{
    return asn1_to_uint8([data, new Uint8Array([0])]);
}

function build_jwk_public(privateKey)
{
   var key ={};

    key.kty = "EC";
    key.crv = privateKey.crv;
    key.x = toBase64(privateKey.x);
    key.y = toBase64(privateKey.y);

    keykey_ops = ["deriveKey", "deriveBits"];
    key.ext = true;

    return key;
}

function AsJWKPublic(call_data, test_params)
{
    call_data.keyData = build_jwk_public(call_data.raw_key.key);
    if (test_params === null) return;
    for (var i=0; i<test_params.length; i++) {
        switch(test_params[i]) {
        case "SetAlg":
            call_data.algorithm = call_data.raw_key.alg;
            break;

        case "X-extend":
            call_data.keyData.x = extend(call_data.keyData.x);
            break;
            
        case "Y-extend":
            call_data.keyData.y = extend(call_data.keyData.y);
            break;

        case "X-shorten":
            call_data.keyData.x = shorten(call_data.keyData.x);
            break;

        case "Y-shorten":
            call_data.keyData.y = shorten(call_data.keyData.y);
            break;
        }
    }
    return;
}

function AsJWKPrivate(call_data, test_params)
{
    call_data.keyData = build_jwk_private(call_data.raw_key.key);
    if (test_params === null) return;
    for (var i=0; i<test_params.length; i++) {
        switch(test_params[i]) {
        case "SetAlg":
            call_data.algorithm = call_data.raw_key.alg;
            break;

        case "X-extend":
            call_data.keyData.x = extend(call_data.keyData.x);
            break;
            
        case "Y-extend":
            call_data.keyData.y = extend(call_data.keyData.y);
            break;

        case "D-extend":
            call_data.keyData.d = extend(call_data.keyData.d);
            break;

        case "X-shorten":
            call_data.keyData.x = shorten(call_data.keyData.x);
            break;

        case "Y-shorten":
            call_data.keyData.y = shorten(call_data.keyData.y);
            break;

        case "D-shorten":
            call_data.keyData.d = shorten(call_data.keyData.d);
            break;
        }
    }
    return;
}

function build_jwk_private(privateKey)
{
    var key ={};

    key.kty = "EC";
    key.crv = privateKey.crv;
    key.x = toBase64(privateKey.x);
    key.y = toBase64(privateKey.y);
    key.d = toBase64(privateKey.d);

    keykey_ops = ["deriveKey", "deriveBits"];
    key.ext = true;

    return key;
}

function build_point(keyData)
{
    if (keyData.useSign) {
        return asn1_to_uint8([new Uint8Array[0x02 + keyData.sign], keyData.x]);
    }
    return asn1_to_uint8([new Uint8Array([0x04]), keyData.x, keyData.y]);
}

function build_asn_public(keyData, asnAlg, ber)
{
    var key = [];
    var rgb;

    var alg = asn1_encode_Algorithm(asnAlg);

    rgb= asn1_encode_bitstring( [build_point(keyData)])

    if (ber) {
        key = [asnSequence, new Uint8Array([0x80]), alg, rgb, new Uint8Array([0, 0])];
    }
    else {
        key = [asnSequence, asn1_encode_length(alg.length+rgb.length), alg, rgb];
    }
    
    
    return asn1_to_uint8(key);
}

function AsASN1Public(call_data, test_params)
{
    call_data.keyData = build_asn_public(call_data.raw_key.key, call_data.raw_key.oid, false);
    if (test_params === null) return;
    if (test_params === null) return;
    for (var i=0; i<test_params.length; i++) {
        switch(test_params[i]) {
        case "SetAlg":
            call_data.algorithm = call_data.raw_key.alg;
            break;

            //  ASN.1 is one byte too long
        case "Extend":
            call_data.keyData = extendBinary(call_data.keyData);
            break;

            //  ASN.1 is one byte too short
        case "Shorten":
            call_data.keyData = shortenBinary(call_data.keyData);
            break;

            // ASN.1 uses BER at the top level
        case "BER":
            call_data.keyData = build_asn_public(call_data.raw_key.key, call_data.raw_key.oid, true);
            break;

            //  Add one to the x axis
        case "invalidPoint":
            call_data.raw_key.key.x[call_data.raw_key.key.x.length-1] += 1;
            call_data.keyData = build_asn_public(call_data.raw_key.key, call_data.raw_key.oid, false);
            break;

        default:
            switch (test_params[i].name) {
            case "USE_OID":
                call_data.keyData = build_asn_public(call_data.raw_key.key, test_params[i].oid, false);
                break
            }
            break;
        }
    }
    return;
}


function build_asn_private(keyMap, asnAlg)
{
    // SEQUENCE {
    //    version:0,
    //    algorithm: SEQUENCE {
    //       OID,
    //       parameters
    //    }
    //    OCTET STRING {
    //       SEQUENCE {
    //          version: 1,
    //          private Key: OCTET STRING,
    //          parameters: [0] ECParameters {{ NamedCurve }} OPTIONAL,
    //          publicKey: [1] BIT STRING OPTIONAL
    //       }
    //    }
    //  }
    //
    //  Good:
    //    1. Omit params inside
    //    2. omit public key inside
    //    3. omit both of them
    //
    //  Bad:
    //    1. external version #
    //    2. External wrong OID
    //    3. External curve and internal curve match - mismatch alg parameter
    //    4. External BER
    //    5. Internal wrong version #
    //    6. Internal wrong curve 
    //    7. Internal curve and external curve different
    //    8. Internal public key wrong
    //    9. Internal BER encoding
    //   10. Internal private key as integer
    //   

    var inner = [];
    if ('InnerVersion' in keyMap) {
        inner.push(asn1_encode_integer([new Uint8Array([keyMap.InnerVersion])]));
    }
    else {
        inner.push(asn1_encode_integer([new Uint8Array([1])]));
    }
    inner.push(asn1_encode_OctetString([keyMap.d]));
    if (!('OmitParams' in keyMap)) {
        inner.push(asnAlg["params"]);
    }
    if (!('OmitPoint' in keyMap)) {
        inner.push(asn1_encode_bitstring( [build_point(keyMap)]));
    }

    var x = asn1_encode_OctetString(inner);
    
    var topLevel = [];

    if ('OuterVersion' in keyMap) {
        topLevel.push(asn1_encode_integer([new Uint8Array([keyMap.OuterVersion])]));
    }
    else {
        topLevel.push(asn1_encode_integer([new Uint8Array([0])]));
    }

    topLevel.push(asn1_encode_Algorithm(asnAlg));
    topLevel.push(x);

    if (keyMap.OuterBer) {
        x.unshift(new Uint8Array([0x30, 0x81]));
        x.push(new Uint8Array([0x0, 0x0]));
        x = asn1_to_uint8([x]);
    }
    else {
        x = asn1_encode(0x30, topLevel);
    }

    return x;
}

function AsASN1Private(call_data, test_params)
{
    call_data.keyData = build_asn_private(call_data.raw_key.key, call_data.raw_key.oid, false);
    
    if (test_params === null) return;
    for (var i=0; i<test_params.length; i++) {
        switch(test_params[i]) {
        case "SetAlg":
            call_data.algorithm = call_data.raw_key.alg;
            break;

        case "Extend":
            call_data.keyData = extendBinary(call_data.keyData);
            break;
            
        case "Shorten":
            call_data.keyData = shortenBinary(call_data.keyData);
            break;
            
        case "BER":
            call_data.keyData = build_asn_private(call_data.raw_key.key, call_data.raw_key.oid, true);
            break;

        case "USE_OID":
            break;

        case "OuterBER":
            call_data.keyData["OuterBER"] = true;
            call_data.keyData = build_asn_private(call_data.raw_key.key, call_data.raw_key.oid, true);
            break;

        case "InnerBER":
            call_data.keyData["InnerBER"] = true;
            call_data.keyData = build_asn_private(call_data.raw_key.key, call_data.raw_key.oid, true);
            break;

        case "OuterVersion":
            call_data.keyData["OuterVeresion"] = 1;
            call_data.keyData = build_asn_private(call_data.raw_key.key, call_data.raw_key.oid, true);
            break;

        case "InnerVersion":
            call_data.keyData["InnerVeresion"] = 0;
            call_data.keyData = build_asn_private(call_data.raw_key.key, call_data.raw_key.oid, true);
            break;

        case "OmitParams":
            call_data.keyData["OmitParams"] = true;
            call_data.keyData = build_asn_private(call_data.raw_key.key, call_data.raw_key.oid, true);
            break;

        case "OmitPoint":
            call_data.keyData["OmitPoint"] = true;
            call_data.keyData = build_asn_private(call_data.raw_key.key, call_data.raw_key.oid, true);
            break;
            
        }
    }
    return;
}

function runOneTest(call_data, test_data)
{
    var t;
    var testString = "{ format:" + call_data.format +
        " algorithm:" + JSON.stringify(call_data.algorithm) +
        " keyUsages:" + JSON.stringify(call_data.keyUsages) +
        " extract:" + call_data.extractable;

    if (call_data.keyData instanceof Uint8Array) {
        testString = testString + " keyData: new UInt8Array([" + call_data.keyData + "]) }";
    }
    else {
        testString = testString + " keyData:" + JSON.stringify(call_data.keyData) + " }";
    }

    delete call_data.raw_key;
    
    t = async_test(call_data.testName);
    self.crypto.subtle.importKey(
        call_data.format, call_data.keyData,
        call_data.algorithm, call_data.extractable,
        call_data.keyUsages).then (
            t.step_func(function(newKey) {
                assert_unreached("Import succeeded and should have failed <call "  + testString + ">");
                t.done();
            }),
            t.step_func(function(err) {
                assert_equals(err.name, test_data["error"], "Check Error Code <call "  + testString + "> " + err.message);
                t.done();
            })
        );
}


var Keys = [
    {keyName:"P-256", key: p256Key, alg:{name:"ECDH", namedCurve:"P-256"}, oid:{oid: ecPublicKey, params:curveP256} },
//    {key: p384Key, alg:{name:"ECDH", namedCurve:"P-384"}, oid:{oid: ecPublicKey, params:curveP384} },
//    {key: p521Key, alg:{name:"ECDH", namedCurve:"P-521"}, oid:{oid: ecPublicKey, params:curveP521} }
];

var testErrorArray = [
    {step:"G2", name:"Normalize", delete:["algorithm/namedCurve"], error:"TypeError"}, // From IDL
    {step:"G2", name:"Normalize", set:{"algorithm/namedCurve":5}, error:"TypeError"}, // From IDL
    {step:"G6a", name:"Format error", conditions:{eq:{format:"raw"}}, callFunction:{name:AsJWKPublic}, error:"TypeError"},
    {step:"G6a", name:"Format error", conditions:{eq:{format:"pkcs8"}}, callFunction:{name:AsJWKPublic}, error:"TypeError"},
    {step:"G6a", name:"Format error", conditions:{eq:{format:"spki"}}, callFunction:{name:AsJWKPublic}, error:"TypeError"},
    {step:"G6b", name:"Format error", conditions:{eq:{format:"jwk"}}, callFunction:{name:AsASN1Public}, error:"TypeError"},

    //  SPKI Import failures
    
    {step:"2.1", name:"Empty Usage", conditions:{eq:{format:"spki"}}, set:{keyUsages:["deriveKey"]}, error:"SyntaxError"},
    
    //  Generate the list of errors we are going to test parsing for
    //  - Good BER value
    //  - Decode failure - type
    //  - Decode failure - length
    {step:"2.3", name:"Parse SPKI error", conditions:{eq:{format:"spki"}}, callFunction:{name:AsASN1Public, params:["BER"]}, error:"DataError"},
    {step:"2.3", name:"Parse SPKI error", conditions:{eq:{format:"spki"}}, callFunction:{name:AsASN1Public, params:["Shorten"]}, error:"DataError"},
    {step:"2.3", name:"Parse SPKI error", conditions:{eq:{format:"spki"}}, callFunction:{name:AsASN1Public, params:["Extend"]}, error:"DataError"},
    {step:"2.3", name:"Parse SPKI error", conditions:{eq:{format:"spki"}}, callFunction:{name:AsASN1Private}, error:"DataError"},
    
    // If params is not an instance of ECParameters that specifies a namedCurve
    {step:"2.6", name:"no named curve", conditions:{eq:{format:"spki"}}, callFunction:{name:AsASN1Public, params:[{name:"USE_OID", oid:{oid:ecPublicKey, params:curveUnknown}}]}, error:"DataError"},
    
    //  Step 2.10 - Need to look at RFC 5480 section 2.2
    //  Step 2.10 - Provide an named Curve for future use
    //  Step 2.10 - Provide a named Curve which is not ever going to be one
    //  Step 2.11 - Not same named curves
    {step:"2.11", name:"Mis-matched curve", conditions:{eq:{format:"spki", "algorithm/namedCurve":"P-256"}}, set:{"algorithm/namedCurve":"P-521"}, error:"DataError"},
    {step:"2.11", name:"Mis-matched curve", conditions:{eq:{format:"spki", "algorithm/namedCurve":"P-256"}}, callFunction:{name:AsASN1Public, params:[{name:"USE_OID", oid:{oid:ecPublicKey, params:curveP521}}]}, error:"DataError"},
    {step:"2.11", name:"Mis-matched curve", conditions:{eq:{format:"spki", "algorithm/namedCurve":"P-384"}}, set:{"algorithm/namedCurve":"P-521"}, error:"DataError"},
    {step:"2.11", name:"Mis-matched curve", conditions:{eq:{format:"spki", "algorithm/namedCurve":"P-384"}}, callFunction:{name:AsASN1Public, params:[{name:"USE_OID", oid:{oid:ecPublicKey, params:curveP521}}]}, error:"DataError"},
    {step:"2.11", name:"Mis-matched curve", conditions:{eq:{format:"spki", "algorithm/namedCurve":"P-521"}}, set:{"algorithm/namedCurve":"P-256"}, error:"DataError"},
    {step:"2.11", name:"Mis-matched curve", conditions:{eq:{format:"spki", "algorithm/namedCurve":"P-521"}}, callFunction:{name:AsASN1Public, params:[{name:"USE_OID", oid:{oid:ecPublicKey, params:curveP256}}]}, error:"DataError"},
  
  //  Step 2.12 - Key is not valid on the curve
    {step:"2.12", name:"Invalid Point", conditions:{eq:{format:"spki"}}, callFunction:{name:AsASN1Public, params:["invalidPoint"]}, error:"DataError"},

    //  "PKCS8"
    //  Step 2.1 - usages contains an entry which is not "deriveKey" or "deriveBits"
    {step:"2.1", name:"Invalid Usages", conditions:{eq:{format:"pkcs8"}}, set:{usages:["deriveKey", "depriveKey"]}, error:"SyntaxError"},

    //  Step 2.3 - error in parsing  "DataError"
    {step:"2.3", name:"Invalid ASN.1", conditions:{eq:{format:"pkcs8"}}, callFunction:{name:AsASN1Private, params:["Extend"]}, error:"DataError"},
    {step:"2.3", name:"Invalid ASN.1", conditions:{eq:{format:"pkcs8"}}, callFunction:{name:AsASN1Private, params:["Shorten"]}, error:"DataError"},
    {step:"2.3", name:"Invalid ASN.1", conditions:{eq:{format:"pkcs8"}}, callFunction:{name:AsASN1Private, params:["OuterBER"]}, error:"DataError"},
    {step:"2.3", name:"Invalid ASN.1", conditions:{eq:{format:"pkcs8"}}, callFunction:{name:AsASN1Private, params:["InnerBER"]}, error:"DataError"},
    {step:"2.3", name:"Invalid ASN.1", conditions:{eq:{format:"pkcs8"}}, callFunction:{name:AsASN1Private, params:["InnerVersion"]}, error:"DataError"},
    {step:"2.3", name:"Invalid ASN.1", conditions:{eq:{format:"pkcs8"}}, callFunction:{name:AsASN1Private, params:["OuterVersion"]}, error:"DataError"},
  
    //  Step 2.4 - wrong oid
    {step:"2.4", name:"Wrong privateKeyAlgorithm", conditions:{eq:{format:"pkcs8"}}, callFunction:{name:AsASN1Private, params:["wrong privateKeyAlg"]}, error:"DataError"},

    

    //  "jwk"
    // Step 2.2 - error while parsing throw "DataError"
    // Step 2.3 - d present usages not deriveKey | derive Bits - "SyntaxError"
    {step:"2.3", name:"bad usages", conditions:{eq:{format:"jwk", keyType:"private"}}, set:{keyUsages:["deriveKey", "sign"]}, error:"SyntaxError"},
    
    // Step 2.4 - d absent - usages not empty- "SyntaxError"
    {step:"2.4", name:"bad usages", conditions:{eq:{format:"jwk", keyType:"public"}}, set:{keyUsages:["deriveKey"]}, error:"SyntaxError"},
    {step:"2.4", name:"bad usages", conditions:{eq:{format:"jwk", keyType:"public"}}, set:{keyUsages:["sign"]}, error:"SyntaxError"},
    {step:"2.4", name:"bad usages", conditions:{eq:{format:"jwk", keyType:"public"}}, set:{keyUsages:["unknown"]}, error:"TypeError"}, // IDL

    // Step 2.5 - "kty" != "EC" - DataError
    {step:"2.5", name:"bad kty", conditions:{eq:{format:"jwk"}}, set:{"keyData/kty":"EC1"}, error:"DataError"},
    {step:"2.5", name:"bad kty", conditions:{eq:{format:"jwk"}}, set:{"keyData/kty":"RSA"}, error:"DataError"},

     // Step 2.6 - "use" present - DataError
    {step:"2.6", name:"use present", conditions:{eq:{format:"jwk"}}, set:{"keyData/use":"sig"}, error:"DataError"},
    
    // Step 2.7 - "key_ops" present and wrong - "DataError"
    {step:"2.7", name:"key ops wrong", conditions:{eq:{format:"jwk"}}, set:{"keyData/key_ops":["sign"]}, error:"DataError"},
    
    // Step 2.8 - "ext" present && != extractable "DataError"
    {step:"2.8", name:"ext false", conditions:{eq:{format:"jwk"}}, set:{"keyData/ext":false, extractable:false}, error:"DataError"},

    // Step 2.10 - mis-match on curve
    {step:"2.10", name:"curve mis-match", conditions:{eq:{format:"jwk", "algorithm/namedCurve":"P-256"}}, set:{"keyData/crv":"P-521"}, error:"DataError"},
    {step:"2.10", name:"curve mis-match", conditions:{eq:{format:"jwk", "algorithm/namedCurve":"P-521"}}, set:{"keyData/crv":"P-256"}, error:"DataError"},
    
    // Step 2.11 - "P-256", "P-384", "P-512" && d present - jwk not 6.2.2 - "DataError"
    {step:"2.11", name:"jwk Params", conditions:{eq:{format:"jwk", keyType:"private"}}, callFunction:{name:AsJWKPrivate, params:["D-extend"]}, error:"DataError"},
    {step:"2.11", name:"jwk Params", conditions:{eq:{format:"jwk", keyType:"private"}}, callFunction:{name:AsJWKPrivate, params:["D-shorten"]}, error:"DataError"},
    {step:"2.11", name:"jwk Params", conditions:{eq:{format:"jwk", keyType:"private"}}, callFunction:{name:AsJWKPrivate, params:["X-extend"]}, error:"DataError"},
    {step:"2.11", name:"jwk Params", conditions:{eq:{format:"jwk", keyType:"private"}}, callFunction:{name:AsJWKPrivate, params:["X-shorten"]}, error:"DataError"},
    {step:"2.11", name:"jwk Params", conditions:{eq:{format:"jwk", keyType:"private"}}, callFunction:{name:AsJWKPrivate, params:["Y-extend"]}, error:"DataError"},
    {step:"2.11", name:"jwk Params", conditions:{eq:{format:"jwk", keyType:"private"}}, callFunction:{name:AsJWKPrivate, params:["Y-shorten"]}, error:"DataError"},

    // Step 2.11 - "P-256", "P-384", "P-512" && d absent - jwk not 6.2.1 - "DataError"
    {step:"2.11", name:"jwk Params", conditions:{eq:{format:"jwk", keyType:"public"}}, callFunction:{name:AsJWKPublic, params:["X-extend"]}, error:"DataError"},
    {step:"2.11", name:"jwk Params", conditions:{eq:{format:"jwk", keyType:"public"}}, callFunction:{name:AsJWKPublic, params:["X-shorten"]}, error:"DataError"},
    {step:"2.11", name:"jwk Params", conditions:{eq:{format:"jwk", keyType:"public"}}, callFunction:{name:AsJWKPublic, params:["Y-extend"]}, error:"DataError"},
    {step:"2.11", name:"jwk Params", conditions:{eq:{format:"jwk", keyType:"public"}}, callFunction:{name:AsJWKPublic, params:["Y-shorten"]}, error:"DataError"},
    
    // Step 2.12 - Other curve unknown - "DataError"

    // "raw"
    // Step 2.1 - curve != "P-256", "P-384", "P-521" - DataError
    // Step 2.2 - usages ! empty - SyntaxError
    // Step 2.3 - extractable false - InvalidAccessError
    // Step 2.4 - Not valid Curve - "DataError"

  
    {step:"G9", name:"usage empty", conditions:{eq:{keyType:"secret"}}, set:{keyUsages:[]}, error:"SyntaxError"},
    {step:"G9", name:"usage empty", conditions:{eq:{keyType:"private"}}, set:{keyUsages:[]}, error:"SyntaxError"},
];

var formats = [
    {testName:"jwk public", callFunction:{name:AsJWKPublic, params:["SetAlg"]}, set:{keyType:"public", keyUsages:[], format:"jwk"}},
    {testName:"jwk private", callFunction:{name:AsJWKPrivate, params:["SetAlg"]}, set:{keyType:"private", keyUsages:["deriveKey"], format:"jwk"}},
    {testName:"spki", callFunction:{name:AsASN1Public, params:["SetAlg"]}, set:{keyType:"public", keyUsages:[], format:"spki"}},
    {testName:"pkcs8", callFunction:{name:AsASN1Private, params:["SetAlg"]}, set:{keyType:"private", keyUsages:[], format:"pkcs8"}}
];

var extractable = [
    {testName: "extract", set:{"extractable":true}},
    {testName: "non-extract", set:{"extractable":false}}
];


function run_test()
{
    var t;

    Keys.forEach(function(key) {
        var key_data = {raw_key:key, testName:key.keyName, extractable:true }

        formats.forEach(function(format) {
            var call_data = applyTest(key_data, format);
            call_data.testName = call_data.testName + " " + format.testName;
            
            for (var iError=0; iError<testErrorArray.length; iError++) {
                if (! checkTest(call_data, testErrorArray[iError])) continue;
            
                var call1 = applyTest(call_data, testErrorArray[iError]);
                call1.testName = call1.testName + " " + testErrorArray[iError].name + " (" + iError.toString() + ")";

                runOneTest(call1, testErrorArray[iError]);
            }
        }
                       )
    }
                )
}




function run_test_pass()
{
    var t;

    Keys.forEach(function(key) {
        var key_data = {raw_key:key, testName:key.keyName, extractable:true };

        formats.forEach(function(format) {
            var call_data = applyTest(key_data, format);
            call_data.testName = call_data.testName + " " + format.testName;

            extractable.forEach(function(extractable) {
                var call_data = applyTest(key_data, format);
                call_data.testName = call_data.testName + " " + format.testName;
            }

                
        
    }
}
