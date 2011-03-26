var fs = require('fs');
var cs = require('coffee-script');

var filename = __dirname + '/dcrypt.coffee';
var coffee = fs.readFileSync(filename, 'utf8');
var js = cs.compile(coffee, { filename : filename });

var vm = require('vm');
vm.runInNewContext(js, {
    exports : exports,
    module : module,
    require : require,
    Buffer : Buffer,
    process : process,
    global : global,
});
