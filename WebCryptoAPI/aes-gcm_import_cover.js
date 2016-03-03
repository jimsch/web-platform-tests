function import_test(t, format, keyData, algorithm, extractable, keyUsages) {
    self.crypto.subtle.importKey(format, keyData, algorithm, extractable, keyUsages).then(
        t.step_func(function(newKey) {
            var i;
            
            //
            //  Verify secret fields match with what we imported
            //

            assert_equals(newKey.algorithm.name, algorithm.name);
            assert_equals(newKey.algorithm.length, algorithm.keyLength);

            if (format == "raw") assert_equals(newKey.type, "secret");
            else if (format == "jwk") {
                 assert_equals(newKey.type, "secret");
            }

            assert_equals(newKey.extractable, extractable);
            assert_equals(newKey.usages.length, keyUsages.length);
            for (i=0; i<keyUsages; i++) {
                assert_in_array(keyUsages[i], newKey.usages);
            }


            //  Try and export the key now

            self.crypto.subtle.exportKey(format, newKey).then(
                t.step_func(function(data) {
                    if (!extractable) assert_unreached("Export should have failed");
                    t.done();
                }),
                t.step_func(function(err) {
                    if (extractable) assert_unreached("Export should have succeeded err="  + err);
                    t.done();
                })
            );
        }),
        t.step_func(function(err) {
            assert_unreached("Import failed with error "  + err);
            t.done();
        })
    );
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

function run_test()
{
    var iExtract, iKey, iUsage;
    var jwk;
    var alg;
    
    for (iExtract=0; iExtract<extractable.length; iExtract++) {
        for (iKey=0; iKey<keys.length; iKey++) {
            alg = {name:"AES-GCM", keyLength:keys[iKey]["keyLength"]};
            
            for (iUsage=0; iUsage<usages.length; iUsage++) {
                t = async_test("AES-GCM Import: cover raw " + extractable[iExtract]["label"] + " " + keys[iKey]["label"] + " " + usages[iUsage]["label"]);
                import_test(t, "raw", keys[iKey]["value"], alg, extractable[iExtract]["value"], usages[iUsage]["value"]);

                t = async_test("AES-GCM Import: cover jwk no alg " + extractable[iExtract]["label"] + " " + keys[iKey]["label"] + " " + usages[iUsage]["label"]);
                jwk = {};
                jwk["kty"] = "oct";
                jwk["k"] = base64js.fromByteArrayURL(keys[iKey]["value"]);
                import_test(t, "jwk", jwk, alg, extractable[iExtract]["value"], usages[iUsage]["value"]);
                
                
                t = async_test("AES-GCM Import: cover jwk w/alg " + extractable[iExtract]["label"] + " " + keys[iKey]["label"] + " " + usages[iUsage]["label"]);
                jwk = {};
                jwk["kty"] = "oct";
                jwk["alg"] = keys[iKey]["alg"];
                jwk["k"] = base64js.fromByteArrayURL(keys[iKey]["value"]);
                import_test(t, "jwk", jwk, alg, extractable[iExtract]["value"], usages[iUsage]["value"]);
                
                t = async_test("AES-GCM Import: cover jwk w/alg " + extractable[iExtract]["label"] + " " + keys[iKey]["label"] + " " + usages[iUsage]["label"] + " key_ops");
                jwk = {};
                jwk["kty"] = "oct";
                jwk["alg"] = keys[iKey]["alg"];
                jwk["k"] = base64js.fromByteArrayURL(keys[iKey]["value"]);
                jwk["key_ops"] = ["encrypt", "wrapKey", "unwrapKey", "decrypt"];
                import_test(t, "jwk", jwk, alg, extractable[iExtract]["value"], usages[iUsage]["value"]);

            }
        }
    }
}
