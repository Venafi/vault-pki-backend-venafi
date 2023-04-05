# Secrets Engine Plugin Versions

Unfortunately, the HashiCorp Vault plugin architecture does not provide developers with a way to
communicate the actual version of their plugins to Vault administrators.  Instead administrators
must rely on the SHA256 hash of the plugin binary to differentiate one version of a plugin from
another.  

Listed below are the SHA256 hashes of plugins from recent official releases, provided to help
simplify the task of identifying which version of the *Venafi PKI Secrets Engine for HashiCorp
Vault* you are currently using.

### v0.12.1
```
b25746156e7db8990fe237c348be741e959d0ca6820436335c5cb39d8b915f58  darwin     venafi-pki-backend
59e2c3e6b389e340c219781655aa9ad6f0f87cd86ed48425e881401925e9e47d  linux      venafi-pki-backend
26d86349b30dec902de9185401c2351f5363dc16f4ae124193708c7d1951a232  linux86    venafi-pki-backend
aeb74aec2282bfc4c50a83998a4554f522dfe526d7034347b0337fab5d2cb613  windows    venafi-pki-backend.exe
cd3efcc4098eace5a4ef950b3245b3c0a4d985ed7b6c5f0f8b533686355cd31a  windows86  venafi-pki-backend.exe
```

### v0.12.0
```
a0e8c07a1fc0d0681bc6faa1c8ee5426ea5ef50e75d632f12929cc37931d8b41  darwin     venafi-pki-backend
2f34f485a1de4e90ff88cf4ce5a84f180879133e68f6c9e0e132ba5eb2411299  linux      venafi-pki-backend
29c5177cf97ef82bef9a46982981d01980ad9e2da528fc35433969e9b0326eb2  linux86    venafi-pki-backend
1ee70b1b268641548f16b5536821b41c6d4bccb60f107d51a0b31859a6778809  windows    venafi-pki-backend.exe
6906708814e1509761bb0f599788f0ddd9e233fe06003ecf6149e34949eafe0d  windows86  venafi-pki-backend.exe
```

### v0.11.0
```
11a661801d52955ad8656eba4f851701b8c62f238f7c8c38bbc2cebfac22ca1a  darwin     venafi-pki-backend
5fb58fdd83be359e5447ff788f8cf1592a76c3038536a9fe9285bb64d5a14367  linux      venafi-pki-backend
5bc4560462dfe725f93b8c144f72f31992d96fbaf429cc7de4c49534ffca6cb4  linux86    venafi-pki-backend
0f61497dac53fd0849f8121ab5b5d9781a99ad34aefdf64793c23104caefd6bc  windows    venafi-pki-backend.exe
cc8cca052374f97cfde93d097c23bed210e59c1fbda7e15460340627e4f8ee79  windows86  venafi-pki-backend.exe
```

### v0.10.6
```
6bb213b74abc5a2c5683b0d48022cc30ba77e55db7cc47f59ba99886737605c8  darwin     venafi-pki-backend
64aae207e0ab6fa57411ca7f3546e45cdbe789ca965f203e274e4d42ae24e583  linux      venafi-pki-backend
cc4d9b1469be8047ee8e3ec3f53ce4849c9b0f6e26eb8f5d8b1d42ccc9a2ea7a  linux86    venafi-pki-backend
12def594aef626a10a2a602322c7cd680fa3f1330d7475045b662bb1a85be8ec  windows    venafi-pki-backend.exe
b662b84d9182dd9ca1afcd61d1a092723531a9952839c58bbe5700a92454273c  windows86  venafi-pki-backend.exe
```

### v0.10.5
```
4d11e2d06a791e387cf56056db688308cd62964c66ed66fcea94109f447c5faf  darwin     venafi-pki-backend
005c5157770ed6f33e8bf4942eac84d0ec6faa6892218596fa2032cd8c32c1be  linux      venafi-pki-backend
5f1018231ce2af525f6643afd13edc5999c9905a90d654aaf5e1d00a8654fba5  linux86    venafi-pki-backend
be9c02fea22e465ff89bea1bde78a017288b0d3b51030aff4c9dc4b6d0c91100  windows    venafi-pki-backend.exe
c6c47f4a9bdbdb9c233fc5746a10c7d243c88f3514151f47c0c5d93d274b031f  windows86  venafi-pki-backend.exe
```

### v0.10.4
```
1ac60f0f6f6f97006d9c63eb445fada7bd80912a1d52f4b8b1a9d70130f3b6b1  darwin     venafi-pki-backend
0807fb4a244aab85d271f80c70f563c4794132549f9d718823f8dbece119ec91  linux      venafi-pki-backend
3f2da03cb28b01ee0aeb70e6a12e1e27db9e27c296bb9149942fe8c7fb6af789  linux86    venafi-pki-backend
f2c3271bbd31b37a9067d293ea07fb1d7170aa751f02fa94f8035365336b98bc  windows    venafi-pki-backend.exe
477650795e10e055696a7521c07882dc505a28ed258afad79e5797e2f9b16c8e  windows86  venafi-pki-backend.exe
```

### v0.10.3
```
a9a6b0e8366867d78531e9865347a105af91167d9bff9c038ab2a52b49c65a5c  darwin     venafi-pki-backend
0b4f067058c31644e64babda27cd93e8fdd82f78065be68d3c5b627204bbe9ff  linux      venafi-pki-backend
f0d1defeedd6ddf1cd747f637f8b4d083e5b7b4d89a4f8852c02f98619e8ade9  linux86    venafi-pki-backend
a7b64553e0e257fa9b075ff324cedb5c92e788160c8cecbf16607e3b3a04cf78  windows    venafi-pki-backend.exe
a77719907d757b7c41f69e6f115755961390c0641f31e86f9929ff68d4d2f850  windows86  venafi-pki-backend.exe
```

### v0.10.2
```
4b11554db47301986f7d591843bfdb0142751030aba669f1cec6b15a04c3b965  darwin     venafi-pki-backend
4a62456882cfdc96a0028d429bf83474e9dc0d56320a7c154e238152cbe13c08  linux      venafi-pki-backend
f16c5f2a5082dcef137a69050a98b2c7c9665accfff85c4179430d76f50fd401  linux86    venafi-pki-backend
594503e35c8f8a4ec84e038116290259ebd6da89d14fa1766ba85128670090c6  windows    venafi-pki-backend.exe
5fd3e489ac6cec64e68a023328f0f7976d81d460181f4ff0f7630d93e2039200  windows86  venafi-pki-backend.exe
```

### v0.10.1
```
4a6b2aedee1c67c1039dc19becd6b82c902ed59ff436338dab674255935395e3  darwin     venafi-pki-backend
21d6101796a528b6c4220c787b9cd5e20f68b658ba653475da2a3cdc583aec51  linux      venafi-pki-backend
d7cc0b1f92206612a6e5b49ae71a86766a912e553870594fe09b622eb8c2e288  linux86    venafi-pki-backend
2d1b631a9888701fb9026e42bda51aa090fcfb27700e92952bf8548c884e7537  windows    venafi-pki-backend.exe
5eed07efda5ea7e28d7d42201e03f0f251feaedb77837a60ea5659555142ba6b  windows86  venafi-pki-backend.exe
```

### v0.10.0
```
a09bdabfc31deb2de8b02646d319a71e5424d6db09bd15c63d7f31d02a9cf93a  darwin     venafi-pki-backend
322c6d74a9e6ac258feac739100c354f94dff64a7c91b605b29b4cef9e3e8cdc  linux      venafi-pki-backend
623a2c207bd2a472108f01c8099e237197df8eef0779898f81151922fefaf752  linux86    venafi-pki-backend
92cb0527c4871c9c73067ba33610777c2ed81e53545bbf46c8f22179980024bb  windows    venafi-pki-backend.exe
c2d2e457515f57a0039519f6281b4c9fd83d9d008e878fdf0133d55cfcf3c0bc  windows86  venafi-pki-backend.exe
```

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
