function import_test(t, format, keyData, algorithm, extractable, keyUsages) {
    self.crypto.subtle.importKey(format, keyData, algorithm, extractable, keyUsages).then(
        t.step_func(function(newKey) {
            //
            //  Verify secret fields match with what we imported
            //

            assert_equals(newKey.algorithm.name, algorithm.name);

            if (format == "raw") assert_equals(newKey.type, "secret");
            else if (format == "jwk") {
                 assert_equals(newKey.type, "secret");
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
var keys = [{label:"128-bits", value: new Uint8Array([1, 2, 3, 4, 5])},
            {label:"192-bits", value: new Uint8Array([1, 2, 3, 4, 5])},
            {label:"256-bits", value: new Uint8Array([1, 2, 3, 4, 5])}];

var algorithm = {name:"AES-GCM"};

function run_test()
{
    for (var extract in extractable) {
        for (var key in keys) {
            t = async_test("AES-GCM Import: cover raw " + key["label"]);
            import_test(t, "raw", key["value"], algorithm, extract["value"], ["encrypt"]);
        }
    }
}
