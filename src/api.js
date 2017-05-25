const {
  classes: Cc, interfaces: Ci, manager: Cm, results: Cr, utils: Cu
} = Components;

Cu.import("resource://gre/modules/ctypes.jsm");

const GAsyncReadyCallback = ctypes.FunctionType(
  ctypes.default_abi, ctypes.void_t,
  [ctypes.voidptr_t, ctypes.voidptr_t, ctypes.voidptr_t]
).ptr;

const SecretSchemaAttribute = new ctypes.StructType("SecretSchemaAttribute", [
  {"name": ctypes.char.ptr},
  {"flags": ctypes.int},
]);

const SecretSchema = new ctypes.StructType("SecretSchema", [
  {"name": ctypes.char.ptr},
  {"flags": ctypes.int},
  {"attributes": new ctypes.ArrayType(SecretSchemaAttribute, 32)},
]);

// Create our schema.
let schema_key_name = ctypes.char.array()("key");
let attrs = new Array(32);
attrs[0] = new SecretSchemaAttribute(schema_key_name, 0);
attrs.fill(new SecretSchemaAttribute, 1);

let schema_name = ctypes.char.array()("my_schema");
let schema = new SecretSchema(schema_name, 0, attrs);

let libsecret = ctypes.open("libsecret-1.so.0");

const secret_password_store = libsecret.declare(
  "secret_password_store", ctypes.default_abi, ctypes.void_t,
  SecretSchema.ptr, ctypes.char.ptr, ctypes.char.ptr, ctypes.char.ptr,
  ctypes.voidptr_t, GAsyncReadyCallback, ctypes.voidptr_t, "..."
);

const secret_password_store_finish = libsecret.declare(
  "secret_password_store_finish", ctypes.default_abi, ctypes.bool,
  ctypes.voidptr_t, ctypes.voidptr_t
);

const secret_password_lookup = libsecret.declare(
  "secret_password_lookup", ctypes.default_abi, ctypes.void_t,
  SecretSchema.ptr, ctypes.voidptr_t, GAsyncReadyCallback, ctypes.voidptr_t,
  "..."
);

const secret_password_lookup_finish = libsecret.declare(
  "secret_password_lookup_finish", ctypes.default_abi, ctypes.char.ptr,
  ctypes.voidptr_t, ctypes.voidptr_t
);

const secret_password_free = libsecret.declare(
  "secret_password_free", ctypes.default_abi, ctypes.voidptr_t, ctypes.char.ptr
);

class API extends ExtensionAPI {
  getAPI(context) {
    return {
      secretstorage: {
        async store(key, password) {
          return new Promise((resolve, reject) => {
            let callback = (source, result, unused) => {
              resolve(secret_password_store_finish(
                result, ctypes.voidptr_t()
              ));
            };

            secret_password_store(
              schema.address(), "session", "my label", password, null,
              GAsyncReadyCallback(callback), null,
              schema_key_name, ctypes.char.array()(key),
              ctypes.voidptr_t()
            );
          });
        },

        async lookup(key) {
          return new Promise((resolve, reject) => {
            let callback = (source, result, unused) => {
              let password = secret_password_lookup_finish(
                result, ctypes.voidptr_t()
              );
              let passwordValue = password.readString();
              secret_password_free(password);
              resolve(passwordValue);
            };

            secret_password_lookup(
              schema.address(), null, GAsyncReadyCallback(callback), null,
              schema_key_name, ctypes.char.array()(key),
              ctypes.voidptr_t()
            );
          });
        },
      }
    };
  }
}
