function clone(obj)
{
    if (obj == null || typeof(obj) !== 'object' || 'isActivClone' in obj) return obj;
    if (obj instanceof Uint8Array) return obj;

    var temp = obj.constructor();
    
    for (var key in obj) {
        if (key == "raw_key") {
            temp[key] = obj[key];
        }
        else if (Object.prototype.hasOwnProperty.call(obj, key)) {
            obj['isActiveClone'] = null;
            temp[key] = clone(obj[key]);
            delete obj['isActiveClone'];
        }
    }

    return temp;
}

function deleteKey(call_data, keyPath)
{
    var keys = keyPath.split("/");
    for (var i=0; i<keys.length-1; i++) {
        if (call_data[keys[i]] == null) return;
        call_data = call_data[keys[i]];
    }
    delete call_data[keys[keys.length-1]];
}

function setValue(call_data, keyPath, value)
{
    var keys = keyPath.split("/");
    for (var i=0; i<keys.length-1; i++) {
        if (call_data[keys[i]] == null) call_data[keys[i]] = {};
        call_data = call_data[keys[i]];
    }
    call_data[keys[keys.length-1]] = value;
}

function getValue(call_data, keyPath)
{
    var keys = keyPath.split("/");
    for (var i=0; i<keys.length-1; i++) {
        if (call_data[keys[i]] == null) return null;
        call_data = call_data[keys[i]];
    }
    return call_data[keys[keys.length-1]];
}

function checkTest(call_data, test_data)
{
    //  If this is the same step then don't run it
    if (call_data["step"] == test_data["step"]) return false;

    if (test_data["conditions"] == null) return true;

    var checks = Object.keys(test_data["conditions"]);

    for (var iKey=0; iKey<checks.length; iKey++) {
        if (checks[iKey] == "eq") {
            var tests = test_data["conditions"]["eq"];
            var keys = Object.keys(tests);

            for (iCheck=0; iCheck<keys.length; iCheck++) {
                var data = getValue(call_data, keys[iCheck]);
                if (data == null || data != tests[keys[iCheck]]) return false;
            }
        }
    }
    return true;
}

function applyTest(call_data, test_data)
{
    var new_data = clone(call_data);

    new_data["step"] = test_data["step"];

    if (test_data["callFunction"] != null) {
        var params = test_data["callFunction"]["params"];
        if (params == undefined || params == null) params = [];
        test_data["callFunction"]["name"](new_data, params);
    }
    
    if (test_data["delete"] != null) {
        var x = test_data["delete"];
        for (var item in x) {
            deleteKey(new_data, x[item]);
        }
    }
    
    if (test_data["set"] != null) {
        var x = test_data["set"];
        for (var item in x) {
            setValue(new_data, item, x[item]);
        }
    }
    
    return new_data;
}
