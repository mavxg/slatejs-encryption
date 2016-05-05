/* Encryption plugin --- support encrypted sections of document */

var openpgp = require('openpgp/src');
var friar   = require('friar');

var DOM         = friar.DOM;
var createClass = friar.createClass;

var cfb = openpgp.crypto.cfb;
var random = openpgp.crypto.random;

//not IE9 or before
var s2r = window.btoa;
var r2s = window.atob;

var keymap = [
	{keys:["ctrl+alt+e"], command:"insert_new_encrypted", args:{},
		context:[
			{key:"breakable", operator:"equals", operand:true, match_all:true}
		]},
	{keys:["cmd+n","e"], command:"insert_new_encrypted", args:{},
		context:[
			{key:"breakable", operator:"equals", operand:true, match_all:true}
		]},
	{keys:["ctrl+e","s"], command:"squash_encrypted_ops"},
];

module.exports = function(context, slatejs) {

var render = slatejs.render;
var renderChildren = render.renderChildren;
var renderers = render.renderers;

var ot = slatejs.type;
var List = ot.List;
var AttributedString = ot.AttributedString;
var sym = ot.sym;
var Selection = ot.Selection;
var Region = ot.Region;

var keyToId = slatejs.keyToId;

/*

//ops are retain from start of the encrypted area. If they contain
// a sequence number then you can apply them in sequence.

(encrypted (keys {id:..., key:...}) (ops ....))
 -- where each op is {r:rev, iv:..., op:encryptedop}

 //we keep the encryped ops on the unencrypted document so we 
 don't need to know how long they are. It also makes squash easier

(encrypt (keys {}) ... objects created by ops ... (ops ....))


*/

var Keys = createClass({
	render: function() {
		var id = keyToId(this.props.keys.id)
		var children = this.props.keys.values.slice(1).map(function(k) {
				return Key({key:k});
			});
		return DOM.div({id:id, className:"content"},[
			DOM.h2({},this.props.title || "Keys"),
			DOM.div({},children)]);
	}
});

var Key = createClass({
	render: function() {
		var key = this.props.key;
		var id = key.id;
		var pub = openpgp.key.readArmored(key.public).keys[0];
		window.pub = pub;
		return DOM.div({id:id},pub.getUserIds().map(
			function(u) { return DOM.p({},u); })
		);
	}
});

var NEW_P = (function() {
	var npl = new List();
	npl.push(sym('p'));
	npl.push(new AttributedString(""));
	return npl.prefix(0,npl.size);
})();

var NEW_OPS = (function() {
	var n = new List();
	n.push(sym('ops'));
	return {op:n.prefix(0,n.size), size:n.size};
})();

function new_encrypt_key(context, editor, pub, id) {
	//generate aes secure key
	var aes = random.getRandomBytes(32); //for aes256
	var apub = pub.armor();
	var keyid = pub.primaryKey.keyid.toHex()
	
	//pgp encrypt the aes key and store it on the document
	var msg = openpgp.message.fromText(s2r(aes));
    msg = msg.encrypt([pub]);
    var armored = openpgp.armor.encode(openpgp.enums.armor.message, 
    	msg.packets.write());
    //add key to encrypted region
    var new_keys = new List();
    new_keys.push(sym('keys'));
    new_keys.push({id:keyid ,public:apub, key:armored});

    var offset = context._snapshot.findEncryptedNodeById(id).offset;
    //register key.
    context.aesKeys[id] = aes;
    //insert the keys.
    var ops = [ot.operations.retain(offset + 2)];
    ops = ops.concat(new_keys.prefix(0,new_keys.size));
    ops = ops.concat(NEW_OPS.op);
    editor.apply(ops); //editor apply not context._apply so the server gets the keys
    //decrypt node

    //var nx = context._snapshot.findEncryptedNodeById(id);
    context.decryptNode(id);

    //add new paragraph
    var start = offset + 2 + new_keys.size + NEW_OPS.size
    ops = [ot.operations.retain(start)];
    ops = ops.concat(NEW_P);
    var selection = new Selection([new Region(start + 4)]);
    editor.apply(ops, selection);
    editor.ensureFocus();
    editor.scrollToCursor();
}

function new_share_key(context, editor, pub, id) {
	//get secret key
	var aes = context.aesKeys[id];
	if (!aes) return;
	var apub = pub.armor();
	var keyid = pub.primaryKey.keyid.toHex();

	var nx = context._snapshot.findEncryptedNodeById(id);
	var offset = nx.offset;
	var node = nx.node;

	var keys = node.index(1);
	var existing = keys.values.slice(1);
	if (existing.some(function(k) {
		return k.id === keyid;
	})) return; // already shared with key
	
	//pgp encrypt the aes key and store it on the document
	console.log("Sharing: " + aes);
	var msg = openpgp.message.fromText(s2r(aes));
	console.log("encrypt")
    msg = msg.encrypt([pub]);
    console.log('armor')
    var armored = openpgp.armor.encode(openpgp.enums.armor.message, 
    	msg.packets.write());
    //add key to encrypted region
    var new_key = {id:keyid ,public:apub, key:armored};
    if (offset === -1)
    	throw "Cannot find node offet to encrypt.";
    //insert the key.
    var ops = [
    	ot.operations.retain(offset + 2 + keys.size - 1),
   		ot.operations.insert(new_key,'obj')
   	];
    editor.apply(ops);
}

var Encrypted = createClass({
	handleEncrypt: function(e) {
		e.preventDefault();
		var id = this.props.obj.id;
		var editor = this.props.editor;
		var context = editor.store().context;
		if (!context.importKey) return;
		var form = this.form.node;
		var akey = form.key.value;
		var passphrase = form.passphrase.value;
		var pub = context.importKey(akey,passphrase);
		if (pub && !(pub.isPrivate()))
			new_encrypt_key(context, editor, pub, id);
	},
	handleUnlock: function(e) {
		e.preventDefault();
		var editor = this.props.editor;
		var context = editor.store().context;
		if (!context.importKey) return;
		var form = this.form.node;
		var akey = form.key.value;
		var passphrase = form.passphrase.value;
		var pub = context.importKey(akey,passphrase);
		if (!pub) {
			this.setState({error:"Invalid key"});
		}
		return;
	},
	toggleUnlock: function(e) {
		this.setState({showUnlockForm:(!this.state.showUnlockForm)});
		e.preventDefault();
		e.stopPropagation();
	},
	render: function() {
		var obj = this.props.obj;
		var path = this.props.path ? this.props.path.slice(0) : [];
			path.push(obj.id);
		var editor = this.props.editor;
		var props = {
			id: keyToId(obj.id),
			className: 'encrypted',
			
		};
		//wrap in form so the edtor recognises the clicks
		var toggle = DOM.form({},[DOM.a({href:'#',
				className:'icon_link', 
				onClick:this.toggleUnlock},[
				DOM.svg({className:'icon'},[
					DOM.use({'xlink:href':"/sprite.svg#lock-locked"})
				])
			])]);

		var keys = obj.index(1);

		var pkey = window.defaultKey || "";

		if (!keys) {
			this.form = DOM.form({
				onSubmit: this.handleEncrypt,
				className:"content pure-form pure-form-stacked",
				spellcheck: false,
			}, [
				DOM.h2({},"New Encrypted Section"),
				
				DOM.div({className:"pure-g"},[
					DOM.textarea({name:"key", className:"pure-u-1",placeholder:"PGP Private Key (Paste)", value:pkey})]),
				DOM.div({className:"pure-g"},[
					DOM.input({name:"passphrase", className:"pure-u-1",type:'password', placeholder:"Passphrase (Optional)", value:""})]),
				DOM.div({className:"pure-g"},[DOM.button({type:'submit', className:"pure-button pure-button-primary"},"Encrypt")]),
			]);
			return DOM.div(props, [
				toggle,this.form]);
		} else {
			var inner = [toggle, Keys({keys:keys, title:'Encrypted By:'})]
			if (this.state.showUnlockForm) {
				this.form = this.form = DOM.form({
					onSubmit: this.handleUnlock,
					className:"content pure-form pure-form-stacked",
					spellcheck: false,
				}, [
					DOM.h2({},"Unlock"),
					
					DOM.div({className:"pure-g"},[
						DOM.textarea({name:"key", className:"pure-u-1",placeholder:"PGP Private Key (Paste)", value:pkey})]),
					DOM.div({className:"pure-g"},[
						DOM.input({name:"passphrase", className:"pure-u-1",type:'password', placeholder:"Passphrase (Optional)", value:""})]),
					DOM.div({className:"pure-g"},[DOM.button({type:'submit', className:"pure-button pure-button-primary"},"Unlock")]),
				]);
				inner.push(this.form);
			}
			return DOM.div(props, inner);
		}
		
	}
});

var Encrypt = createClass({
	toggleShare: function(e) {
		this.setState({showKeys:(!this.state.showKeys)});
		e.preventDefault();
		e.stopPropagation();
	},
	handleShare: function(e) {
		e.preventDefault(); //don't submit form
		e.stopPropagation();
		var editor = this.props.editor;
		if (!context.importKey) return;
		var form = this.shareForm.node;
		var akey = form.key.value;
		var pub = context.importKey(akey);
		if (pub && !(pub.isPrivate())) {
			new_share_key(context, editor, pub, this.props.obj.id);
			this.setState({showKeys:false});
		}

	},
	render: function() {
		var obj = this.props.obj;
		var editor = this.props.editor;
		var path = this.props.path ? this.props.path.slice(0) : [];
			path.push(obj.id);
		var props = {
			id: keyToId(obj.id),
			className: 'encrypted',
			
		};
		var children = obj.tail();
		if (children.length === 0) children = ["\u00A0"];
		var toggle = DOM.form({},[DOM.a({href:'#',
				className:'icon_link', 
				onClick:this.toggleShare},[
				DOM.svg({className:'icon'},[
					DOM.use({'xlink:href':"/sprite.svg#lock-unlocked"})
				])
			])]);
		this.shareForm = DOM.form({
			onSubmit: this.handleShare,
			className:"content pure-form pure-form-stacked shareForm",
			spellcheck: false}, [
				DOM.div({className:"pure-g"},[
					DOM.textarea({name:"key", className:"pure-u-1",placeholder:"Paste PGP Public Key to share", value:""}),
					DOM.button({type:'submit', className:"pure-button pure-button-primary"},"Share")
				])
			]);
		var inner = [toggle];
		if (this.state.showKeys) {
			inner.push(Keys({keys:obj.index(1), title:'Encrypted By:'}));
			inner.push(this.shareForm);
		}
		inner.push(DOM.div({className:"content"}, 
			renderChildren(children, this.props.selection, obj.id, editor, path)));
		return DOM.div(props,inner);
	}
});

//register renderers
renderers.encrypted = Encrypted;
renderers.encrypt = Encrypt;
// must be here and not in the plugin load as the plugin load is after
// first render

	return function(editor) {


	//(doc -> region -> (arg) -> op) -> selection -> ops
	function bySelection(f, selection, arg) {
		var doc = editor.document();
		var ops = [];
		var _selection = selection || editor.selection();
		function _replace(region) {
			var op = f(doc, region, arg);
			ops = ot.compose(ops, ot.transform(op,ops));
		}
		_selection.forEachR(_replace);
		return ops;
	}

	//this is the same as section break but with
	//the ability to insert things between the
	//sections
	function _insert_new(doc, region, between) {
		var as = doc.attributesAt(region.begin());
		var breaks = [];
		var ops = [];
		var a;
		for (var i = as.length - 1; i >= 0; i--) {
			var x = as[i];
			breaks.push(x);
			ops.push(ot.operations.pop);
			if (x.type === 'list' && x.node.head().sym === 'section') break;
		};
		if (x.node.head().sym !== 'section') return []; //could not find section to break;
		ops = ops.concat(between);
		while ((a = breaks.pop())) {
			if (a.type === 'list') {
				ops.push(ot.operations.pushA(a.attributes));
				ops.push(ot.operations.insert(a.node.head().sym,'sym'));
			} else {
				ops.push(ot.operations.pushS());
			}
		}
		return doc.replace(region, ops);
	}

	var NEW_ENC = new List();
	NEW_ENC.push(sym('encrypted'));

	function insert_new(args) {
		var between = NEW_ENC.prefix(0,NEW_ENC.size);
		var sel = editor.selection();
		if (sel.regions.length !== 1) return;
		var region = sel.regions[0];
		var doc = editor.document();
		var ops = _insert_new(doc, region, between);
		editor.apply(ops);
		//if we have a key decrypt the region
		var context = editor.store().context;
		//console.log('Default key')
		//console.log(context.defaultKey)
		if (context.defaultKey !== undefined) {
			var off = 0;
			for (var i = 0; i < ops.length; i++) {
				var op = ops[i];
				if (op.op === 'insert' &&
					op.type === 'sym' &&
					op.value === 'encrypted')
					break;
				switch (op.op) {
					case 'retain':
					case 'insert':
						off += op.n;
						break;
				}
			};
			var node = editor.document().nodeAt(off-1).node;
			//console.log(off)
			//console.log(node)
			if (!(node && node instanceof List &&
				node.head().sym === 'encrypted' &&
				node.values.length === 1)) return;
			new_encrypt_key(context, editor, context.defaultKey, node.id);
		}
	}
	insert_new.description = function(args) {
		return "Insert new encrypted section.";
	};

	function squash() {
		context.squash();
	}
	squash.description = function() {
		return "Squash encrypted ops";
	};

	return {
		commands: {
			insert_new_encrypted: insert_new,
			squash_encrypted_ops: squash,
		},
		keymap: keymap,
	};
};

}

