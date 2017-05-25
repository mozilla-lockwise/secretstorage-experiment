const {
  classes: Cc, interfaces: Ci, manager: Cm, results: Cr, utils: Cu
} = Components;

Cu.import("resource://gre/modules/ctypes.jsm");

const SecretSchemaAttribute = new ctypes.StructType("SecretSchemaAttribute", [
  {"name": ctypes.char.ptr},
  {"flags": ctypes.int},
]);

const SecretSchema = new ctypes.StructType("SecretSchema", [
  {"name": ctypes.char.ptr},
  {"flags": ctypes.int},
  {"attributes": new ctypes.ArrayType(SecretSchemaAttribute, 32)},
]);

let attr_name = ctypes.char.array()("string");
let attrs = new Array(32);
attrs[0] = new SecretSchemaAttribute(attr_name, 0);
attrs.fill(new SecretSchemaAttribute, 1);

let schema_name = ctypes.char.array()("my_schema");
let schema = new SecretSchema(schema_name, 0, attrs);

let libsecret = ctypes.open("libsecret-1.so.0");

let secret_password_store_sync = libsecret.declare(
  "secret_password_store_sync", ctypes.default_abi, ctypes.bool,
  SecretSchema.ptr, ctypes.char.ptr, ctypes.char.ptr, ctypes.char.ptr,
  ctypes.voidptr_t, ctypes.voidptr_t, "..."
);

let secret_password_lookup_sync = libsecret.declare(
  "secret_password_lookup_sync", ctypes.default_abi, ctypes.char.ptr,
  SecretSchema.ptr, ctypes.voidptr_t, ctypes.voidptr_t, "..."
);

class API extends ExtensionAPI {
  getAPI(context) {
    return {
      secretstorage: {
        async store(password) {
          return secret_password_store_sync(
            schema.address(), "session", "my label", password, null, null,
            ctypes.char.array()("string"), ctypes.char.array()("hello"),
            ctypes.voidptr_t()
          );
        },

        async lookup() {
          let value = secret_password_lookup_sync(
            schema.address(), null, null,
            ctypes.char.array()("string"), ctypes.char.array()("hello"),
            ctypes.voidptr_t()
          );
          return value.readString();
        },
      }
    };
  }
}
