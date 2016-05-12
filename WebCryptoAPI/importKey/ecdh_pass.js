//
//
//


var ecPublicKey = new Uint8Array([6, 7, 42, 134, 72, 206, 61, 2, 1]);

var curveP256 = new Uint8Array([6, 8, 42, 134, 72, 206, 61, 3, 1, 7]);
var curveP384 = new Uint8Array([6, 5, 0x2b, 0x81, 4, 0, 0x22]); 
var curveP521 = new Uint8Array([6, 5, 0x2b, 0x81, 4, 0, 0x23]); 


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

var oidSha1 = new Uint8Array([ 0x30, 0x9, 0x06, 0x05,  0x2b, 0xe, 0x03, 0x02, 0x1a, 0x05, 0x00 ]);
var oidSha256 = new Uint8Array([ 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00 ]);
var oidSha384 = new Uint8Array([ 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00 ]);
var oidSha512 = new Uint8Array([ 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00 ]);


function toBase64(data)
{
    if (data[0] == 0) {
        data = data.subarray(1);
    }
    return base64js.fromByteArrayURL(data);
}

function build_jwk_public(privateKey)
{
   var key ={};

    key["kty"] = "EC";
    key["crv"] = privateKey["crv"];
    key["x"] = toBase64(privateKey["x"]);
    key["y"] = toBase64(privateKey["y"]);

    key["key_ops"] = ["deriveKey", "deriveBits"];
    key["ext"] = true;

    return key;
}

function build_jwk_private(privateKey)
{
    var key ={};

    key["kty"] = "EC";
    key["crv"] = privateKey["crv"];
    key["x"] = toBase64(privateKey["x"]);
    key["y"] = toBase64(privateKey["y"]);
    key["d"] = toBase64(privateKey["d"]);

    key["key_ops"] = ["deriveKey", "deriveBits"];
    key["ext"] = true;

    return key;
}

function build_point(keyData)
{
    return asn1_to_uint8([new Uint8Array([0x04]), keyData["x"],keyData["y"]]);
}

function build_asn_public(keyData, asnAlg)
{
    var key = [];
    var rgb;

    var alg = asn1_encode_Algorithm(asnAlg);

    rgb= asn1_encode_bitstring( [build_point(keyData)])
    
    rgb = asn1_to_uint8(rgb);

    key = [asnSequence, asn1_encode_length(alg.length+rgb.length), alg, rgb];
    
    return asn1_to_uint8(key);
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

    var x = asn1_encode(0x30, [].concat(
        asn1_encode_integer([new Uint8Array([1])]),
        asn1_encode_OctetString([keyMap["d"]])//,
//        asnAlg["params"],
//        asn1_encode_bitstring( build_point(keyMap))
    ));
    x = asn1_encode_OctetString(x);

    x = asn1_encode(0x30, [].concat(
        asn1_encode_integer([new Uint8Array([0])]),
        asn1_encode_Algorithm(asnAlg),
        x));
    return asn1_to_uint8(x);
}

function import_test(t, format, keyData, algorithm, extractable, keyUsages) {
    self.crypto.subtle.importKey(format, keyData, algorithm, extractable, keyUsages).then(
        t.step_func(function(newKey) {
            //
            //  Verify public fields match with what we imported
            //

            assert_equals(newKey.algorithm.name, algorithm.name);
            assert_equals(newKey.algorithm.namedCurve, algorithm.namedCurve);

            if (format == "pkcs8") assert_equals(newKey.type, "private");
            else if (format == "spki") assert_equals(newKey.type, "public");
            else if (format == "jwk") {
                if ('d' in keyData) assert_equals(newKey.type, "private");
                else assert_equals(newKey.type, "public");
            }

            assert_equals(newKey.extractable, extractable);
            assert_array_equals(newKey.usages, keyUsages);

            //  Try and export the key now

            self.crypto.subtle.exportKey(format, newKey).then(
                t.step_func(function(data) {
                    if (!extractable) assert_unreached("Export should have failed");
                    t.done();
                }),
                t.step_func(function(err) {
                    if (extractable) assert_unreached("Export should have succeeded err=" + err);
                    t.done();
                })
            );
        }),
        t.step_func(function(err) {
            assert_unreached("Import failed with error " + err);
            t.done();
        })
    );
}

var jwkAlgs = [ null, "RS1", "RS256", "RS384", "RS512" ];

var extractableNames = ["not-extractable","extractable"];
var extractable = [false, true];

//
//  Run a test on importing the same key in a variety of different ways
//
//  Matrix of test is:
//     extractable: false, true
//     format x type: jwk public, jwk private, pkcs8, spki
//     algorithm.hash.name: SHA-1, SHA-256, SHA-384, SHA-512
//     key data algorithm: rsaEncryption, hash algorithm w/rsaEncryption
//              (i.e. sha1WithRsaEncryption, sha256WithRSAEncryption,
//                    sha384WithRSAEncrypiton, sha512WithRSAEncryption)
//
//  Total Test Count: 64
//
//  Additional test - import jwk w/ only d private value
//    Expect a change to the spec so that this goes away as it is not supported by anybody
//
//  Current test is over a single key, this should be adaquate but can be adapted to
//      multiple keys if needed.
//

function run_test_old()
{
    var asn;
    var i,j;
    var t;
    var jwkKey;
    var jsonPublic = build_jwk_public(asnPrivate);
    var jsonPrivate = build_jwk_private(asnPrivate);

    t = async_test("RSASSA Import: cover  jwk private-d only exportable none " + algArrayName[i]);
    import_test(t, "jwk", jwkPrivateDOnly, alg256, true, ["sign"] );

    for (j=0; j<2; j++) {
        for (i=1; i<5; i++) {
            jwkKey = jsonPublic;
            delete jwkKey["alg"];

            t = async_test("RSASSA Import: cover  jwk public " + extractableNames[j] + " none " + algArrayName[i]);
            import_test(t, "jwk", jwkKey, algArray[i], extractable[j], ["verify"] );

            jwkKey = jsonPrivate;
            delete jwkKey["alg"];

            t = async_test("RSASSA Import: cover  jwk private " + extractableNames[j] + " none " + algArrayName[i]);
            import_test(t, "jwk", jwkKey, algArray[i], extractable[j], ["sign"] );
        }

        for (i=1; i<5; i++) {
            jwkKey = jsonPublic;
            jwkKey["alg"] = jwkAlgs[i];

            t = async_test("RSASSA Import: cover  jwk public " + extractableNames[j] + " " + jwkAlgs[i] + " " + algArrayName[i]);
            import_test(t, "jwk", jwkKey, algArray[i], extractable[j], ["verify"] );

            jwkKey = jsonPrivate;
            jwkKey["alg"] = jwkAlgs[i];

            t = async_test("RSASSA Import: cover  jwk private " + extractableNames[j] + " " + jwkAlgs[i] + " " + algArrayName[i]);
            import_test(t, "jwk", jwkKey, algArray[i], extractable[j], ["sign"] );
        }

        var asnPublic = build_asn_public(rsaKey);
        var asnPrivate = build_asn_private(rsaKey);

        for (i=1; i<5; i++) {
            asnPublic[2] = oid2Array[0];
            asn = asn1_to_uint8(asnPublic);

            t = async_test("RSASSA Import: cover  asn public " + extractableNames[j] + " " + oidNames[0] + " " + algArrayName[i]);
            import_test(t, "spki", asn, algArray[i], extractable[j], ["verify"] );

            asnPrivate[3] = oid2Array[0];
            asn = asn1_to_uint8(asnPrivate);

            t = async_test("RSASSA Import: cover  asn private " + extractableNames[j] + " " + oidNames[0] + " " + algArrayName[i]);
            import_test(t, "pkcs8", asn, algArray[i], extractable[j], ["sign"] );
        }

        for (i=1; i<5; i++) {
            asnPublic[2] = oid2Array[i];
            asn = asn1_to_uint8(asnPublic);

            t = async_test("RSASSA Import: cover  asn public " + extractableNames[j] + " " + oidNames[i] + " " +algArrayName[i]);
            import_test(t, "spki", asn, algArray[i], extractable[j], ["verify"] );

            asnPrivate[3] = oid2Array[i];
            asn = asn1_to_uint8(asnPrivate);

            t = async_test("RSASSA Import: cover  asn private " + extractableNames[j] + " " + oidNames[i] + " " +algArrayName[i]);
            import_test(t, "pkcs8", asn, algArray[i], extractable[j], ["sign"] );
        }
    }
}

var Keys = [
    {key: p256Key, alg:{name:"ECDH", namedCurve:"P-256"}, oid:{oid: ecPublicKey, params:curveP256} },
    {key: p384Key, alg:{name:"ECDH", namedCurve:"P-384"}, oid:{oid: ecPublicKey, params:curveP384} },
    {key: p521Key, alg:{name:"ECDH", namedCurve:"P-521"}, oid:{oid: ecPublicKey, params:curveP521} }
];


var testArray[] = [
  {step:"0", name:"default"},
  {step:"6", name:"format - raw"},
  {step:"6", name:"format - pkcs8"},
  {step:"6", name:"format - spki"},
  {step:"6", name:"format - jwk"},
];

var testErrorArray[] = [
  {step:"G2", name:"Normalize", delete:["algorithms/namedCurve"], error:"UNKNOWN"},
  {step:"G2", name:"Normalize", set:{"algorithms/namedCurve":5}, error:"UNKNOWN"},
  {step:"G6a", name:"Format error", conditions:{eq:[format:"raw"]}, function:{name:AsJWKPublic}, error:"TypeError"},
  {step:"G6a", name:"Format error", conditions:{eq:[format:"pkcs8"]}, function:{name:AsJWKPublic}, error:"TypeError"},
  {step:"G6a", name:"Format error", conditions:{eq:[format:"spki"]}, function:{name:AsJWKPublic}, error:"TypeError"},
  {step:"G6b", name:"Format error", conditions:{eq:[format:"jwk"]}, function:{name:AsASN1Public}, error:"TypeError"},
  {step:"2.1", name:"Empty Usage", conditions:{eq:{format:"spki"}}, set:{usages:["X"]}, error:"SyntaxError"},
  //  Generate the list of errors we are going to test parsing for
  //  - Good BER value
  //  - Decode failure - type
  //  - Decode failure - length
  {step:"2.3", name:"Parse SPKI error", conditions:{eq:{format:"spki"}}, function:{name:"AsASN1Public", params:"Errro1"}, error:"DataError"},
  // If params is not an instance of ECParameters that specifies a namedCurve
  {step:"2.6", name:"no named curve", conditions:{eq:{format:"spki"}}, error:"DataError"},
  //  Step 2.10 - Need to look at RFC 5480 section 2.2
  //  Step 2.10 - Provide an named Curve for future use
  //  Step 2.10 - Provide a named Curve which is not ever going to be one
  //  Step 2.11 - Not same named curves
  {step:"2.11", name:"Mis-matched curve", conditions:{eq:{format:"spki", "algorithm/namedCurve":"P-256"}}, set:{"algorithm/namedCurve":"P-521"}, error:"DataError"},
  {step:"2.11", name:"Mis-matched curve", conditions:{eq:{format:"spki", "algorithm/namedCurve":"P-256"}}, function:{name:"AsASN1Public", params:{"namedCurve":"P-521"}}, error:"DataError"},
  {step:"2.11", name:"Mis-matched curve", conditions:{eq:{format:"spki", "algorithm/namedCurve":"P-384"}}, set:{"algorithm/namedCurve":"P-521"}, error:"DataError"},
  {step:"2.11", name:"Mis-matched curve", conditions:{eq:{format:"spki", "algorithm/namedCurve":"P-384"}}, function:{name:"AsASN1Public", params:{"namedCurve":"P-521"}}, error:"DataError"},
  {step:"2.11", name:"Mis-matched curve", conditions:{eq:{format:"spki", "algorithm/namedCurve":"P-521"}}, set:{"algorithm/namedCurve":"P-256"}, error:"DataError"},
  {step:"2.11", name:"Mis-matched curve", conditions:{eq:{format:"spki", "algorithm/namedCurve":"P-521"}}, function:{name:"AsASN1Public", params:{"namedCurve":"P-256"}}, error:"DataError"},
  
  //  Step 2.12 - Key is not valid on the curve
  {step:"2.12", name:"Invalid Point", conditions:{eq:{format:"spki"}}, function:{name:"AsASN1Public", params:{invalidPoint:true}}, error:"DataError"},

  //  Step 2.1 - usages contains an entry which is not "deriveKey" or "deriveBits"
  {step:"2.1", name:"Invalid Usages", conditions:{eq:{format:"pkcs8"}}, set:{usages:["deriveKey", "depriveKey"]], error:"SyntaxError"},

  //  Step 2.3 - error in parsing  "DataError"
  
  //  Step 2.4 - wrong oid
  {step:"2.4", name:"Wrong privateKeyAlgorithm", conditions:{eq:{format:"pkcs8"}, 
  
  
  
  {step:"G9", name:"usage empty", conditions:{eq:{keyType:"secret"}}, set:{usages:[]}, error:"SyntaxError"},
  {step:"G9", name:"usage empty", conditions:{eq:{keyType:"private"}}, set:{usages:[]}, error:"SyntaxError"}},
];

function run_test()
{
    var t;

    for (j=0; j<Keys.length; j++) {
        var key = Keys[j];

        t = async_test("ECDH Import: jwk public " + key["alg"]["namedCurve"]);
        import_test(t, "jwk", build_jwk_public(key["key"]), key["alg"], true, []);

        t = async_test("ECDH Import: jwk private " + key["alg"]["namedCurve"]);
        import_test(t, "jwk", build_jwk_private(key["key"]), key["alg"], true, ["deriveKey"]);

        t = async_test("ECDH Import: spki " + key["alg"]["namedCurve"]);
        import_test(t, "spki", build_asn_public(key["key"], key["oid"]), key["alg"], true, []);

        t = async_test("ECDH Import: pkcs8 " + key["alg"]["namedCurve"]);
        import_test(t, "pkcs8", build_asn_private(key["key"], key["oid"]), key["alg"], true, ["deriveKey"]);

        t = async_test("ECDH Import: raw " + key["alg"]["namedCurve"]);
        import_test(t, "raw", build_point(key["key"]), key["alg"], true, ["deriveKey"]);
    }
}
