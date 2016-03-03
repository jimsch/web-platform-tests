function check_jwk_key(key, jwk)
{
    assert_own_property(jwk, "kty");
    assert_equals(jwk["kty"], "oct", "Key type not oct but is " + jwk["kty"]);
    assert_own_property(jwk, "alg");
    switch(key.algorithm.length) {
    case 128:
        assert_equals(jwk["alg"], "A128GCM");
        break;
    case 192:
        assert_equals(jwk["alg"], "A192GCM");
        break;
    case 256:
        assert_equals(jwk["alg"], "A256GCM");
        break;
    }
    assert_own_property(jwk, "k");
    assert_own_property(jwk, "key_ops");
    assert_array_equals(jwk["key_ops"], key.usages);
    assert_own_property(jwk, "ext");
    assert_equals(jwk["ext"], true);

    
}

function check_raw_key(key, raw)
{
    //  Currently no checks
    assert_equals(raw.byteLength, key.algorithm.length/8);
}

function export_test(t, format, key)
{
    self.crypto.subtle.exportKey(format, key).then(
        t.step_func(function(keyData) {
            //  Check the data for the key we just exported.
            switch (format) {
            case "jwk":
                check_jwk_key(key, keyData)
                break;
            case "raw":                check_raw_key(key, keyData);
                break;
            }

            //  We should be able to import what we just exported

            self.crypto.subtle.importKey(format, keyData, key.algorithm, true, key.usages).then(
                t.step_func(function(newKey) {
                    t.done();
                }),
                t.step_func(function(err) {
                    assert_unreached("Reimport failed with error " + err);
                    t.done();
                }));
        }),
        t.step_func(function(err) {
            assert_unreached("Export failed with error " + err);
            t.done();
        })
    )
}

var extractable = [{label:"not-extractable", value:false},
                   {label:"extractable", value:true}];
var keys = [
    {label:"128-bits", alg:"A128GCM", keyLength: 128,
     value: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])},
    {label:"192-bits", alg:"A192GCM", keyLength: 192,
     value: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24])},
    {label:"256-bits", alg:"A256GCM", keyLength: 256,
     value: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])}
];

var algorithm = {name:"AES-GCM"};
var usages = [
    {label:"encrypt", value:["encrypt"]},
    {label:"decrypt", value:["decrypt"]},
    {label:"wrapKey", value:["wrapKey"]},
    {label:"unwrapKey", value:["unwrapKey"]},
    {label:"encrypt+wrapKey", value:["encrypt", "wrapKey"]},
    {label:"decrypt+unwrapKey", value:["decrypt", "unwrapKey"]},
    {label:"encrypt+decrypt+wrapKey+unwrapKey",value:["encrypt", "wrapKey", "decrypt", "unwrapKey"]}
];

function run_tests(key)
{
    var t;

    t = async_test("AES-GCM export: " + key.algorithm.name + " " + key.type + " " + key.algorithm.length + " jwk");
    export_test(t, "jwk", key);

    t = async_test("AES-GCM export: " + key.algorithm.name + " " + key.type + " " + key.algorithm.length + " raw");
    export_test(t, "raw", key);
}

var keys = [
    {label:"128-bits", alg:"A128GCM", keyLength: 128},
    {label:"192-bits", alg:"A192GCM", keyLength: 192},
    {label:"256-bits", alg:"A256GCM", keyLength: 256}
];

function run_test()
{
    var iKey;
    var p = [];
    var alg = {name:"AES-GCM"} ;

    for (iKey=0; iKey<keys.length; iKey++) {
        alg["length"] = keys[iKey]["keyLength"];
        p.push(self.crypto.subtle.generateKey(alg, true, ["encrypt"]).then(
            function(newKey) {
                run_tests(newKey);
            },
            function(err) {
                console.log.bind(console, "No support for " + alg["algorithm"] + " " + err);
            }
        ));
    }

    Promise.all(p).then(function(x) { done(); });
}
