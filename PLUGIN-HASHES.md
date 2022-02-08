# Secrets Engine Plugin Versions

Unfortunately, the HashiCorp Vault plugin architecture does not provide developers with a way to
communicate the actual version of their plugins to Vault administrators.  Instead administrators
must rely on the SHA256 hash of the plugin binary to differentiate one version of a plugin from
another.  

Listed below are the SHA256 hashes of plugins from recent official releases, provided to help
simplify the task of identifying which version of the *Venafi PKI Secrets Engine for HashiCorp
Vault* you are currently using.

### v0.9.1
```
b64502fab669236981f5d4af39624285cb4ae2f6b02a12b8cc5eacd589b96b18  darwin     venafi-pki-backend
acfee893ef1363810d433f8456644b36ed6342778ff7d2ad0c17ec2e7d13630b  linux      venafi-pki-backend
30f05f537bb17e6569b67aaee97c7586f9acc6d88f723284059d4e9b4ae91e0b  linux86    venafi-pki-backend
deca347d1793fd51f0ea051f16330e6c08a0d8675db298f9727a1fb7215c9e25  windows    venafi-pki-backend.exe
8bf18d683b346a43759a62dbb3b0658e56795c0994c516a5d30fe694f8e7fd3a  windows86  venafi-pki-backend.exe
```

### v0.9.0
```
b467450dfefe0293593c3ccfd9b65436c9df9571ca6b40d717435dc92dfe1b69  darwin     venafi-pki-backend
ef633c05af5224dd2bc992ff3ac1e56a5849b2c6aab9ee9f67840d4c20208e15  linux      venafi-pki-backend
bbd152216855d2f441f4374da320eb99784d089464efbbd8db3da76f778dd89b  linux86    venafi-pki-backend
e61fd27138b2639f6be578da72836214b1c3ce05a93a3294a079f714586db5b9  windows    venafi-pki-backend.exe
54139afe86a98d58d2300134e161df2300fa91242dfe095a6b820d0b8a4c65f0  windows86  venafi-pki-backend.exe
```

### v0.8.3
```
a943069891e2d725e88d74e002189223442647df6939a5120ded983a120d7ab2  darwin     venafi-pki-backend
4440ee7d3cde5fe2aaab2f0276d645d37aef8edc86651cc183c31c22cd39ea67  linux      venafi-pki-backend
8d892cc449f20c840fefc44ac2d176e13e64f9449e72bf0f059a36008caf62e0  linux86    venafi-pki-backend
4c84988add1ae2323872ce9b036e996aabec2cfc62d25d1523546eeaa5bde1da  windows    venafi-pki-backend.exe
4580b7464f586d148a4a269f84ce21a8bb79131d65020de0b7b46d4848b0fe72  windows86  venafi-pki-backend.exe
```

### v0.8.2
```
1b81bcf1620dcdf073fcabe0129837038d8205fc8047a847b2c8a968a8943dc9  darwin     venafi-pki-backend
2376ff1173c0613181ae37c96b11f93ab323ed2936a8112009050e583dd8acc6  darwin86   venafi-pki-backend
1682d4f697436dbcc8b1fd3f7b894ff99678292ba37af5016b40c187d26c7e9e  linux      venafi-pki-backend
9bdc4466b1ad0ca48b4f31b35f1d2ea464d0b9f59d7004e21e4556ab43f19ce4  linux86    venafi-pki-backend
0896d010122884e9430a6cfc66e5b02b8731ef0212eb0c47d0c3ce1bc4d1b217  windows    venafi-pki-backend.exe
4828e87332e1799a6b111eca5e343fe11cc1839eac7e2179ea9f2ed227d5c248  windows86  venafi-pki-backend.exe
```

### v0.8.1
```
463ee6810a1e0637b2ab3011f4bc0299a45a4e0a41843e14d2570e06e254dcca  darwin     venafi-pki-backend
0435045f430b56796c04e579074bfea9b3a3e38044e2bd468501cebd0daf3291  darwin86   venafi-pki-backend
f5c0b6c71328d70af9ad88bf067d5d47f15273b45c5b633de87bb1a5cd2e15ea  linux      venafi-pki-backend
25e5059bb9fff75f683124bfbffee7c28c283137e7f8c2684fae789b528f9b0c  linux86    venafi-pki-backend
82698781fcc99a73548d77c84aa2f427f793fa2f5238877d0814316eb6f69067  windows    venafi-pki-backend.exe
5c8fb78367af780dede27a733b4c26e442a5695d9bda654bad853210040c3970  windows86  venafi-pki-backend.exe
```

### v0.8.0
```
459a014f6abbe2f2cab24974efea3f935eeafabe00de67be938d91ada6ad3d96  darwin     venafi-pki-backend
cf8a6e8b06d50e308d187cad4bbf4e78b0fc385e7dd0e370ca0b7f117351c3a7  darwin86   venafi-pki-backend
018e0fef396103489df57ba4911d75309cbd21026d6b24643db25985846d1fd8  linux      venafi-pki-backend
bfa0b57abbe93122c96bddfd5652d14c7117da0384678010a00987c5839e95aa  linux86    venafi-pki-backend
9470ce43996fac1bb645ea6fd40290f6667b6604e855eb07582e957459d61cf5  windows    venafi-pki-backend.exe
38aebbdf41f70fec5da908768e59848c27cdbc12af61fcc0fdc551b03747d32c  windows86  venafi-pki-backend.exe
```
