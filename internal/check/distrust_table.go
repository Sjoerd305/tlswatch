package check

import (
	"strings"
	"time"
)

// The table was compiled on 18 October 2026 from the root programs' own
// material: the Chrome Root Program's posts and root_store.textproto, the
// Mozilla bugs and CA/Root_CA_Lifecycles, Apple's support article 121668
// and Microsoft's Trusted Root Program notices. Every anchor is keyed by
// the SHA-256 fingerprint of its certificate as the programs publish it;
// its public key hash and key ID come from that certificate. Chrome's dates
// for removals are when the root left the Chrome Root Store source, as
// Chrome announces no release for them. Mozilla's 2027 root-age date is its
// published target; the release that ships it may come a few weeks later.

// distrustAnchors are the CA certificates the events cover, by fingerprint.
var distrustAnchors = map[string]Anchor{
	"d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4": {Name: "AAA Certificate Services", SPKI: "bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3", SKI: "a0110a233e96f107ece2af29ef82a57fd030a4b4"},
	"ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab5573894179b93fa": {Name: "AC RAIZ FNMT-RCM", SPKI: "2fc5667a4b9a2678ed6ac6ad25465fcbf6094bfcd9504097c7a8fa47ade5e888", SKI: "f77dc5fdc4e89a1b7764a7f51da0ccbf87609a6d"},
	"0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7": {Name: "AffirmTrust Commercial", SPKI: "6c464b9a5b233a5e874da765c26f045010d2ddcff45794f0b4c7e4aafa501495", SKI: "9d93c6538b5ecaaf3f9f1e0fe59995bc24f6948f"},
	"0a81ec5a929777f145904af38d5d509f66b5e2c58fcdb531058b0e17f3f0b41b": {Name: "AffirmTrust Networking", SPKI: "94072ad3f58f70f93098e5a5f6c04c96c710bd849d83184919ae90eb890ae400", SKI: "071fd2e79cdac26ea240b4b07a50105074c4c8bd"},
	"70a73f7f376b60074248904534b11482d5bf0e698ecc498df52577ebf2e93b9a": {Name: "AffirmTrust Premium", SPKI: "c7f43b4cf5b71568294f822b53762605f6ddd15cadece739e9e2c3cba61e9d67", SKI: "9dc067a60c22d926f545aba665521127d845ac63"},
	"bd71fdf6da97e4cf62d1647add2581b07d79adf8397eb4ecba9c5e8488821423": {Name: "AffirmTrust Premium ECC", SPKI: "3219b09114ff495a3eb6eb00c2efeab34002ae5f0a56c7679ea087a3fa037e4f", SKI: "9aaf297ac011353526513000c36afe40d5aed63c"},
	"f356bea244b7a91eb35d53ca9ad7864ace018e2d35d5f8f96ddf68a6f41aa474": {Name: "Atos TrustedRoot 2011", SPKI: "e5ca37bc7b6c361979bc6b123ca9a1db019046d7ff5f57dfb854b19d10b0682f", SKI: "a7a506b12ca60960eed197e970aebc3b196cdb21"},
	"04048028bf1f2864d48f9ad4d83294366a828856553f3b14303f90147f5d40ef": {Name: "Autoridad de Certificacion Firmaprofesional CIF A62634068", SPKI: "3b0d73b4be4a854adc3e51d7ef9fa48aefbb2cdd824d67bdc7d7d09a2abc2d43", SKI: "65cdebab351e003e7ed574c01cb473470e1a642f"},
	"16af57a9f676b0ab126095aa5ebadef22ab31119d644ac95cd4b93dbf3f26aeb": {Name: "Baltimore CyberTrust Root", SPKI: "63d9af9b47b1064d49a10e7b7fd566dbc8caa399459bfc2829c571ad8c6ef34a", SKI: "e59d5930824758ccacfa085436867b3ab5044df0"},
	"e3b6a2db2ed7ce48842f7ac53241c7b71d54144bfb40c11f3f1d0b42f5eea12d": {Name: "Certigna", SPKI: "510d20e5c47f63cf666b20f61af62bc099a42ac824ffa443a2da7c90b1808a91", SKI: "1aedfe413990b42459be01f252d545f65a39dc11"},
	"eaa962c4fa4a6bafebe415196d351ccd888d4f53f3fa8ae6d7c466a94e6042bb": {Name: "certSIGN ROOT CA", SPKI: "dbc1e3a15238a0483bcdb8fdec616e03e705a48e2a501157cadf3b9c7311c5e5", SKI: "e08c9bdb2549b3f17c86d6b242870bd06ba0d9e4"},
	"5c58468d55f58e497e743982d2b50010b6d165374acf83a7d4a32db768c4408e": {Name: "Certum Trusted Network CA", SPKI: "aa2630a7b617b04d0a294bab7a8caaa5016e6dbe604837a83a85719fab667eb5", SKI: "0876cdcb07ff24f6c5cdedbb90bce284374675f7"},
	"063e4afac491dfd332f3089b8542e94617d893d7fe944e10a7937ee29d9693c0": {Name: "Chambers of Commerce Root - 2008", SPKI: "ced43902ab5fb57b442322dc0e172a4fb55f7178b808f94e780a6fd6cc6bd818", SKI: "f924ac0fb2b5f879c0fa60881bc4d94d029e1719"},
	"0c2cd63df7806fa399ede809116b575bf87989f06518f9808c860503178baf66": {Name: "COMODO Certification Authority", SPKI: "006d7be7555dd82026442c4f1a27a80e89a1989cb87b34448ed2194c18196d5e", SKI: "0b58e58bc64c1537a440a930a921be47365a56ff"},
	"1793927a0614549789adce2f8f34f7f0b66d0f3ae3a3b84d21ec15dbba4fadc7": {Name: "COMODO ECC Certification Authority", SPKI: "e7ca91bbfbb18788057b3a8070446ea5291160194102f7dcc3b9848c63cb9cd5", SKI: "7571a7194819bc9d9dea4147df94c4487799d379"},
	"52f0e1c4e58ec629291b60317f074671b85d7ea80d5b07273463534b32b40234": {Name: "COMODO RSA Certification Authority", SPKI: "82b5f84daf47a59c7ab521e4982aefa40a53406a3aec26039efa6b2e0e7244c1", SKI: "bbaf7e023dfaa6f13c848eadee3898ecd93232d4"},
	"2605875afcc176b2d66dd66a995d7f8d5ebb86ce120d0e7e9e7c6ef294a27d4c": {Name: "ComSign Global Root CA", SPKI: "c06c872fc2d0ac08d78d421981fbda4e35500d0946f79894edd21ac29dec0719", SKI: "024593d80d4862ac69baae065b3efbaa269150b1"},
	"49e7a442acf0ea6287050054b52564b650e4f49e42e348d6aa38e039e957b1c1": {Name: "D-TRUST Root Class 3 CA 2 2009", SPKI: "eca0f181402ce7a8652b31b4d036df247e3a30b7f41a50d91ec4f90b006b43a1", SKI: "fdda14c49f30de21bd1e4239fcab632349e0f184"},
	"eec5496b988ce98625b934092eec2908bed0b0f316c2d4730c84eaf1f3d34881": {Name: "D-TRUST Root Class 3 CA 2 EV 2009", SPKI: "ff342fb6c4c8bd30a4706f73489539f19e6e48cc05f46254654f6610dbc540e9", SKI: "d3948a4c62132a192eccaf728a7d36d79a1cdc67"},
	"3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c": {Name: "DigiCert Assured ID Root CA", SPKI: "23f2edff3ede90259a9e30f40af8f912a5e5b3694e6938440341f6060e014ffa", SKI: "45eba2aff492cb82312d518ba7a7219df36dc80f"},
	"4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161": {Name: "DigiCert Global Root CA", SPKI: "aff988906dde12955d9bebbf928fdcc31cce328d5b9384f21c8941ca26e20391", SKI: "03de503556d14cbb66f0a3e21b1bc397b23dd155"},
	"7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf": {Name: "DigiCert High Assurance EV Root CA", SPKI: "5a889647220e54d6bd8a16817224520bb5c78e58984bd570506388b9de0f075f", SKI: "b13ec36903f8bf4701d498261a0802ef63642bc3"},
	"bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3": {Name: "emSign ECC Root CA - C3", SPKI: "eabc185c4e82d942b1a5978ba3c0181487d6b3b9974e5c49f72f6d0bd9637150", SKI: "fb5a48d0802040f2a8e90007691977a7e6c3f4cf"},
	"125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f": {Name: "emSign Root CA - C1", SPKI: "b7408b4d2be0238ba37004dd34e276c6019bd2f24c9db7d4980f5f6c359a4bcc", SKI: "fea1e0701e2a0339525a42be5c91857a18aa4db5"},
	"73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c": {Name: "Entrust Root Certification Authority", SPKI: "6dbfae00d37b9cd73f8fb47de65917af00e0dddf42dbceac20c17c0275ee2095", SKI: "6890e467a4a65380c78666a4f1f74b43fb84bd6d"},
	"02ed0eb28c14da45165c566791700d6451d7fb56f0b2ab1d3b8eb070e56edff5": {Name: "Entrust Root Certification Authority - EC1", SPKI: "fea2b7d645fba73d753c1ec9a7870c40e1f7b0c561e927b985bf711866e36f22", SKI: "b763e71add8de908a65583a4e06a504165114249"},
	"43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339": {Name: "Entrust Root Certification Authority - G2", SPKI: "76ee8590374c715437bbca6bba6028eadde2dc6dbbb8c3f610e851f11d1ab7f5", SKI: "6a72267ad01eef7de73b6951d46c8d9f901266ab"},
	"db3517d1f6732a2d5ab97c533ec70779ee3270a62fb4ac4238372460e6f01e88": {Name: "Entrust Root Certification Authority - G4", SPKI: "36d7c79f3d089a0ff79972d90923dea5ca76b4ccbaf7c2751cb152e9494f52d0", SKI: "9f38c45623c339e8a0716ce8544ce4e83ab1bf67"},
	"6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177": {Name: "Entrust.net Certification Authority (2048)", SPKI: "1ea3c5e43ed66c2da2983a42a4a79b1e906786ce9f1b58621419a00463a87d38", SKI: "55e481d11180bed889b908a331f9a1240916b970"},
	"c0a6f4dc63a24bfdcf54ef2a6a082a0a72de35803e2ff5ff527ae5d87206dfd5": {Name: "ePKI Root Certification Authority", SPKI: "62554c17005543b237215f04268dcd2fd1c470240ad3c8660e25ae2c59630f55", SKI: "1e0cf7b667f2e192260945c055392e773f424aa2"},
	"136335439334a7698016a0d324de72284e079d7b5220bb8fbd747816eebebaca": {Name: "Global Chambersign Root - 2008", SPKI: "927a1b8562280576d048c50321ada43d8703d2d9521a18c28b8c46cc6aae4efd", SKI: "b909ca9c1edbd36c3a6baeed54f15b9306352e5e"},
	"cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b": {Name: "GlobalSign", SPKI: "706bb1017c855c59169bad5c1781cf597f12d2cad2f63d1a4aa37493800ffb80", SKI: "8ff04b7fa82e4524ae4d50fa639a8bdee2dd1bbc"},
	"ebd41040e4bb3ec742c9e381d31ef2a41a48b6685c96e7cef3c1df6cd4331c99": {Name: "GlobalSign Root CA", SPKI: "2bcee858158cf5465fc9d76f0dfa312fef25a4dca8501da9b46b67d1fbfa1b64", SKI: "607b661a450d97ca89502f7d04cd34a8fffcfd4b"},
	"9a296a5182d1d451a2e37f439b74daafa267523329f90f9a0d2007c334e23c9a": {Name: "GLOBALTRUST 2020", SPKI: "fee8af929175687f4638a3fc983db8ecd0e5e2a83e737f3fb77b4c22fcbac0a6", SKI: "dc2e1fd1613779e4abd5d5b31271683d6a689c22"},
	"c3846bf24b9e93ca64274c0ec67c1ecc5e024ffcacd2d74019350e81fe546ae4": {Name: "Go Daddy Class 2 Certification Authority", SPKI: "5632d97bfa775bf3c99ddea52fc2553410864016729c52dd6524c8a9c3b4489f", SKI: "d2c4b0d291d44c1171b361cb3da1fedda86ad4e3"},
	"45140b3247eb9cc8c5b4f0d7b53091f73292089e6e5a63e2749dd3aca9198eda": {Name: "Go Daddy Root Certificate Authority - G2", SPKI: "2a8f2d8af0eb123898f74c866ac3fa669054e23c17bc7a95bd0234192dc635d0", SKI: "3a9a8507106728b6eff6bd05416e20c194da0fde"},
	"44b545aa8a25e65a73ca15dc27fc36d24c1cb9953a066539b11582dc487b4833": {Name: "Hellenic Academic and Research Institutions ECC RootCA 2015", SPKI: "bb52086d0639e8db332775ac8f4e8435d92ceb00f4e24f28fc0eabe240772e80", SKI: "b4220b829924010e9cbbe40efdbffb972093992a"},
	"a040929a02ce53b4acf4f2ffc6981ce4496f755e6d45fe0b2a692bcd52523f36": {Name: "Hellenic Academic and Research Institutions RootCA 2015", SPKI: "50cc86ba96db3263c79a43ead07553d9f56659e6907e72d8c026637a1cdc85dc", SKI: "711567c8c8c9bd755d72d038186a9df37124540b"},
	"f015ce3cc239bfef064be9f1d2c417e1a0264a0a94be1f0c8d121864eb6949cc": {Name: "HiPKI Root CA - G1", SPKI: "79caaf5347e6e4a94c8e78a98496fc74020f809ede13f220fab6104c8ded329f", SKI: "f27717fa5ea8fef63d71d568bac9460c38d8afb0"},
	"30d0895a9a448a262091635522d1f52010b5867acae12c78ef958fd4f4389f2f": {Name: "IdenTrust Public Sector Root CA 1", SPKI: "58dd61feb36ea7d258724371709149cb121337864cacb2d0999ad20739d06477", SKI: "e371e09ed8a742d9db71916b9493ebc3a3d114a3"},
	"2530cc8e98321502bad96f9b1fba1b099e2d299e0f4548bb914f363bc0d4531f": {Name: "Izenpe.com", SPKI: "952c2039c0243eb515dd73d83fc3643184874feb0862a9837731ed9b4742e17a", SKI: "1d1c650ea8f2257bb491cfe4b1b1e6bd55746c05"},
	"3c5f81fea5fab82c64bfa2eaecafcde8e077fc8620a7cae537163df36edbf378": {Name: "Microsec e-Szigno Root CA 2009", SPKI: "616167201433aea6c8e5e3070afcaf6749188f814bd1abb179ae8dad3abf26ec", SKI: "cb0fc6df4243cc3dcbb54823a11a7aa62abb3468"},
	"6c61dac3a2def031506be036d2a6fe401994fbd13df9c8d466599274c446ec98": {Name: "NetLock Arany (Class Gold) Főtanúsítvány", SPKI: "f48badd7df6a06690d0ae31373b12855f8dedb14517f362a313101cc98cc6b35", SKI: "ccfa6793f0b6b8d0a5c01ef353fd8c53df83d796"},
	"8a866fd1b276b57e578e921c65828a2bed58e9f2f288054134b7f1f4bfc9cc74": {Name: "QuoVadis Root CA 1 G3", SPKI: "86a68f050034126a540d39db2c5f917ef66a94fb9619fa1ecd827cea46ba0cb0", SKI: "a397d6f35ea210e1ab459f3c17643cee01709ccc"},
	"85a0dd7dd720adb7ff05f83d542b209dc7ff4528f7d677b18389fea5e5c49e86": {Name: "QuoVadis Root CA 2", SPKI: "8fd112c3c8370f147d5ccd3a7d865eb8dd540783bac69fc60088e3743ff33378", SKI: "1a8462bc484c332504d4eed0f603c41946d1946b"},
	"18f1fc7f205df8adddeb7fe007dd57e3af375a9c4d8d73546bf4f1fed1e18d35": {Name: "QuoVadis Root CA 3", SPKI: "0c7acaa710226720bbc940349ee2e6148652a89dbf406a232c895f6dc78ebb9a", SKI: "f2c013e082433efbee2f673296355cdbb8cb02d0"},
	"4200f5043ac8590ebb527d209ed1503029fbcbd41ca1b506ec27f15ade7dac69": {Name: "Secure Global CA", SPKI: "2596904dc4d699ae20c2cef4dce47f285937d77464ac370746f52dea76ba0c28", SKI: "af4404c2417e4883db4e3902ecec847ae6cec9a4"},
	"bf0feefb9e3a581ad5f9e9db7589985743d261085c4d314f6f5d7259aa421612": {Name: "SecureSign RootCA11", SPKI: "bb4128ec9620f2d2a49ce8e2c4e257aebad93a0f11c56b5fa4b00e23759fa39d", SKI: "5bf84d4fb2a586d43ad2f1639aa0be09f657b7de"},
	"f1c1b50ae5a20dd8030ec9f6bc24823dd367b5255759b4e71b61fce9f7375d73": {Name: "SecureTrust CA", SPKI: "77290717614b25f12964ebdb38b5f83caadc0f6c36b0777f880fc6dee1d339cc", SKI: "4232b616fa04fdfe5d4b7ac3fdf74c401d5a43af"},
	"513b2cecb810d4cde5dd85391adfc6c2dd60d87bb736d2b521484aa47a0ebef6": {Name: "Security Communication RootCA2", SPKI: "3380709af3b096be3cc2a40548142c0a520028db09e2cb77ae2206616ab6cbb4", SKI: "0a85a9776505987c4081f80f972c38f10aec3ccf"},
	"1465fa205397b876faa6f0a9958e5590e40fcc7faa4fb7c2c8677521fb5fb658": {Name: "Starfield Class 2 Certification Authority", SPKI: "15f14ac45c9c7da233d3479164e8137fe35ee0f38ae858183f08410ea82ac4b4", SKI: "bf5fb7d1cedd1f86f45b55acdcd710c20ea988e7"},
	"2ce1cb0bf9d2f9e102993fbe215152c3b2dd0cabde1c68e5319b839154dbb7f5": {Name: "Starfield Root Certificate Authority - G2", SPKI: "808d68b3fab4884a5f971ace7d10550d7a95a163774f3ec36afffb213fbe4c74", SKI: "7c0c321fa7d9307fc47d68a362a8a1ceab075b27"},
	"568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5": {Name: "Starfield Services Root Certificate Authority - G2", SPKI: "2b071c59a0a0ae76b0eadb2bad23bad4580b69c3601b630c2eaf0613afa83f92", SKI: "9c5f00dfaa01d7302b3888a2b86d4a9cf2119183"},
	"62dd0be9b9f50a163ea0f8e75c053b1eca57ea55c8688f647c6881f2c8357b95": {Name: "SwissSign Gold CA - G2", SPKI: "40fcfc28875dccbfebcbdf6cd7433312da63c4efcf3bd7b1b505c22020ae0274", SKI: "5b257b96a465517eb839f3c078665ee83ae7f0ee"},
	"91e2f5788d5810eba7ba58737de1548a8ecacd014598bc0b143e041b17052552": {Name: "T-TeleSec GlobalRoot Class 2", SPKI: "6106c0e3a0a299831875127bd7d3cc1859803d511cac11eb6e0840dd166fc10e", SKI: "bf5920360079a0a0226b8cd5f261d2b82ccb824a"},
	"fd73dad31c644ff1b43bef0ccdda96710b9cd9875eca7e31707af3e96d522bbd": {Name: "T-TeleSec GlobalRoot Class 3", SPKI: "8d767764b3cbda08929d072a22a561f4dcdd1bc57d3cbddc948c47d2b47f9122", SKI: "b503f7763b61826a12aa1853eb032194bffececa"},
	"dd6936fe21f8f077c123a1a521c12224f72255b73e03a7260693e8a24b0fa389": {Name: "TeliaSonera Root CA v1", SPKI: "10ba3485ca8bb6880ab9531a4063e4001555561c7f2e055165f49b2d74fc5f6b", SKI: "f08f593800b3f58f9a960cd5ebfa7baa17e81312"},
	"97552015f5ddfc3c8788c006944555408894450084f100867086bc1a2bb58dc8": {Name: "Trustwave Global Certification Authority", SPKI: "2e06cae1fc20b200e6fb748557a4444bec9317dfff2e4151669e0f7944f0a9e0", SKI: "99e019670d62db76b3da3db85be8fd42d2310e87"},
	"945bbc825ea554f489d1fd51a73ddf2ea624ac7019a05205225c22a78ccfa8b4": {Name: "Trustwave Global ECC P256 Certification Authority", SPKI: "497128fc90656b87290482b223efb72240fe9c421e79938de5f8110cb0be9056", SKI: "a34106ac906dd14aeb75a54a1099b3b1a18b4af7"},
	"55903859c8c0c3ebb8759ece4e2557225ff5758bbd38ebd48276601e1bd58097": {Name: "Trustwave Global ECC P384 Certification Authority", SPKI: "828b0eeff24654e8ff5841a29dd5d4e3ed30952ca43425a79283407208d39d16", SKI: "55a98489d2c132bd18cb6ca6074ec8e79dbe8290"},
	"bfd88fe1101c41ae3e801bf8be56350ee9bad1a6b9bd515edc5c6d5b8711ac44": {Name: "TWCA Root Certification Authority", SPKI: "92c46879626ef2cc1ecea50c72fb5e385844095f21cbf3b283cb82e6b9fc6a58", SKI: "6a385b268dde8b5af24f7a54831918e30835a6ba"},
	"4ff460d54b9c86dabfbcfc5712e0400d2bed3fbc4d4fbdaa86e06adcd2a9ad7a": {Name: "USERTrust ECC Certification Authority", SPKI: "2021917e98263945c859c43f1d73cb4139053c414fa03ca3bc7ee88614298f3b", SKI: "3ae10986d4cf19c29676744976dce035c663639a"},
	"e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2": {Name: "USERTrust RSA Certification Authority", SPKI: "c784333d20bcd742b9fdc3236f4e509b8937070e73067e254dd3bf9c45bf4dde", SKI: "5379bf5aaa2b4acf5480e1d89bc09df2b20366cb"},
	"cecddc905099d8dadfc5b1d209b737cbe2c18cfb2c10c0ff0bcf0d3286fc1aa2": {Name: "XRamp Global Certification Authority", SPKI: "051cf9fa95e40e9b83edaeda6961f6168c7879c4660172479cdd51ab03cea62b", SKI: "c64fa23d066384099cce62e404ac8d5cb5e9b61b"},
}

// Distrusts is the distrust calendar: root-program distrust events, from
// the programs' own announcements. A new or changed row raises
// DistrustTable.
var Distrusts = []DistrustEvent{
	{CA: "Entrust", Program: "Chrome", IssuedAfter: at("2024-11-11T23:59:59Z"), BySCT: true, Effective: at("2024-11-12T00:00:00Z"), Description: "Chrome 131 distrusts new Entrust certificates", Link: "https://security.googleblog.com/2024/06/sustaining-digital-certificate-security.html",
		Anchors: of("73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c", "02ed0eb28c14da45165c566791700d6451d7fb56f0b2ab1d3b8eb070e56edff5", "43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339", "db3517d1f6732a2d5ab97c533ec70779ee3270a62fb4ac4238372460e6f01e88", "6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177", "0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7", "0a81ec5a929777f145904af38d5d509f66b5e2c58fcdb531058b0e17f3f0b41b", "70a73f7f376b60074248904534b11482d5bf0e698ecc498df52577ebf2e93b9a", "bd71fdf6da97e4cf62d1647add2581b07d79adf8397eb4ecba9c5e8488821423")},
	{CA: "Entrust", Program: "Chrome", Effective: at("2025-04-24T00:00:00Z"), Description: "removed from the Chrome Root Store", Link: "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto",
		Anchors: of("6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177")},
	{CA: "Entrust", Program: "Chrome", Effective: at("2025-07-09T00:00:00Z"), Description: "removed from the Chrome Root Store", Link: "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto",
		Anchors: of("0a81ec5a929777f145904af38d5d509f66b5e2c58fcdb531058b0e17f3f0b41b", "70a73f7f376b60074248904534b11482d5bf0e698ecc498df52577ebf2e93b9a", "bd71fdf6da97e4cf62d1647add2581b07d79adf8397eb4ecba9c5e8488821423")},
	{CA: "Entrust", Program: "Chrome", Effective: at("2025-10-28T00:00:00Z"), Description: "removed from the Chrome Root Store", Link: "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto",
		Anchors: of("db3517d1f6732a2d5ab97c533ec70779ee3270a62fb4ac4238372460e6f01e88")},
	{CA: "Entrust", Program: "Chrome", Effective: at("2025-12-16T00:00:00Z"), Description: "removed from the Chrome Root Store", Link: "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto",
		Anchors: of("73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c", "43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339", "02ed0eb28c14da45165c566791700d6451d7fb56f0b2ab1d3b8eb070e56edff5", "0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7")},
	{CA: "Entrust", Program: "Mozilla", IssuedAfter: at("2024-11-30T23:59:59Z"), Effective: at("2025-01-07T00:00:00Z"), Description: "Firefox 134 distrusts new Entrust certificates", Link: "https://bugzilla.mozilla.org/show_bug.cgi?id=1922387",
		Anchors: of("73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c", "02ed0eb28c14da45165c566791700d6451d7fb56f0b2ab1d3b8eb070e56edff5", "43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339", "6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177", "0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7", "0a81ec5a929777f145904af38d5d509f66b5e2c58fcdb531058b0e17f3f0b41b", "70a73f7f376b60074248904534b11482d5bf0e698ecc498df52577ebf2e93b9a", "bd71fdf6da97e4cf62d1647add2581b07d79adf8397eb4ecba9c5e8488821423")},
	{CA: "Entrust", Program: "Mozilla", Effective: at("2025-01-07T00:00:00Z"), Description: "Firefox 134 no longer trusts it for websites", Link: "https://bugzilla.mozilla.org/show_bug.cgi?id=1919913",
		Anchors: of("db3517d1f6732a2d5ab97c533ec70779ee3270a62fb4ac4238372460e6f01e88")},
	{CA: "Entrust", Program: "Mozilla", Effective: at("2025-05-27T00:00:00Z"), Description: "Firefox 139 no longer trusts it for websites (root age)", Link: "https://bugzilla.mozilla.org/show_bug.cgi?id=1957685",
		Anchors: of("6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177")},
	{CA: "Entrust", Program: "Mozilla", Effective: at("2026-05-19T00:00:00Z"), Description: "Firefox 151 no longer trusts it for websites", Link: "https://bugzilla.mozilla.org/show_bug.cgi?id=2017348",
		Anchors: of("43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339", "02ed0eb28c14da45165c566791700d6451d7fb56f0b2ab1d3b8eb070e56edff5")},
	{CA: "Entrust", Program: "Mozilla", Effective: at("2026-05-19T00:00:00Z"), Description: "removed in Firefox 151", Link: "https://bugzilla.mozilla.org/show_bug.cgi?id=2017460",
		Anchors: of("0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7", "0a81ec5a929777f145904af38d5d509f66b5e2c58fcdb531058b0e17f3f0b41b", "70a73f7f376b60074248904534b11482d5bf0e698ecc498df52577ebf2e93b9a", "bd71fdf6da97e4cf62d1647add2581b07d79adf8397eb4ecba9c5e8488821423")},
	{CA: "Entrust", Program: "Mozilla", Effective: at("2026-05-19T00:00:00Z"), Description: "Firefox 151 no longer trusts it for websites (root age)", Link: "https://wiki.mozilla.org/CA/Root_CA_Lifecycles",
		Anchors: of("73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c")},
	{CA: "Entrust", Program: "Apple", IssuedAfter: at("2024-11-15T23:59:59Z"), Effective: at("2024-11-16T00:00:00Z"), Description: "Apple distrusts new Entrust certificates", Link: "https://support.apple.com/en-us/121668",
		Anchors: of("73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c", "02ed0eb28c14da45165c566791700d6451d7fb56f0b2ab1d3b8eb070e56edff5", "43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339", "db3517d1f6732a2d5ab97c533ec70779ee3270a62fb4ac4238372460e6f01e88", "6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177", "0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7", "0a81ec5a929777f145904af38d5d509f66b5e2c58fcdb531058b0e17f3f0b41b", "70a73f7f376b60074248904534b11482d5bf0e698ecc498df52577ebf2e93b9a", "bd71fdf6da97e4cf62d1647add2581b07d79adf8397eb4ecba9c5e8488821423")},
	{CA: "Entrust", Program: "Microsoft", IssuedAfter: at("2025-04-16T00:00:00Z"), Effective: at("2025-04-16T00:00:00Z"), Description: "Microsoft distrusts new Entrust certificates for server authentication", Link: "https://learn.microsoft.com/en-us/security/trusted-root/2025/february-2025",
		Anchors: of("73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c", "02ed0eb28c14da45165c566791700d6451d7fb56f0b2ab1d3b8eb070e56edff5", "43df5774b03e7fef5fe40d931a7bedf1bb2e6b42738c4e6d3841103d3aa7f339", "db3517d1f6732a2d5ab97c533ec70779ee3270a62fb4ac4238372460e6f01e88", "6dc47172e01cbcb0bf62580d895fe2b8ac9ad4f873801e0c10b9c837d21eb177", "0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7", "0a81ec5a929777f145904af38d5d509f66b5e2c58fcdb531058b0e17f3f0b41b", "70a73f7f376b60074248904534b11482d5bf0e698ecc498df52577ebf2e93b9a", "bd71fdf6da97e4cf62d1647add2581b07d79adf8397eb4ecba9c5e8488821423")},
	{CA: "Chunghwa Telecom", Program: "Chrome", IssuedAfter: at("2025-07-31T23:59:59Z"), BySCT: true, Effective: at("2025-08-05T00:00:00Z"), Description: "Chrome 139 distrusts new Chunghwa Telecom certificates", Link: "https://blog.google/security/sustaining-digital-certificate-security-chrome-root-store-changes/",
		Anchors: of("c0a6f4dc63a24bfdcf54ef2a6a082a0a72de35803e2ff5ff527ae5d87206dfd5", "f015ce3cc239bfef064be9f1d2c417e1a0264a0a94be1f0c8d121864eb6949cc")},
	{CA: "Chunghwa Telecom", Program: "Chrome", Effective: at("2026-08-17T00:00:00Z"), Description: "removed from the Chrome Root Store", Link: "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto",
		Anchors: of("c0a6f4dc63a24bfdcf54ef2a6a082a0a72de35803e2ff5ff527ae5d87206dfd5")},
	{CA: "Chunghwa Telecom", Program: "Mozilla", IssuedAfter: at("2025-04-15T23:59:59Z"), Effective: at("2025-07-22T00:00:00Z"), Description: "Firefox 141 distrusts new certificates (root age)", Link: "https://bugzilla.mozilla.org/show_bug.cgi?id=1974299",
		Anchors: of("c0a6f4dc63a24bfdcf54ef2a6a082a0a72de35803e2ff5ff527ae5d87206dfd5")},
	{CA: "Chunghwa Telecom", Program: "Mozilla", Effective: at("2026-08-18T00:00:00Z"), Description: "removed in Firefox 154", Link: "https://bugzilla.mozilla.org/show_bug.cgi?id=2052097",
		Anchors: of("c0a6f4dc63a24bfdcf54ef2a6a082a0a72de35803e2ff5ff527ae5d87206dfd5")},
	{CA: "NetLock", Program: "Chrome", IssuedAfter: at("2025-07-31T23:59:59Z"), BySCT: true, Effective: at("2025-08-05T00:00:00Z"), Description: "Chrome 139 distrusts new NetLock certificates", Link: "https://blog.google/security/sustaining-digital-certificate-security-chrome-root-store-changes/",
		Anchors: of("6c61dac3a2def031506be036d2a6fe401994fbd13df9c8d466599274c446ec98")},
	{CA: "NetLock", Program: "Chrome", Effective: at("2026-08-17T00:00:00Z"), Description: "removed from the Chrome Root Store", Link: "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto",
		Anchors: of("6c61dac3a2def031506be036d2a6fe401994fbd13df9c8d466599274c446ec98")},
	{CA: "NetLock", Program: "Apple", IssuedAfter: at("2024-11-15T23:59:59Z"), Effective: at("2024-11-16T00:00:00Z"), Description: "Apple distrusts new NetLock certificates", Link: "https://support.apple.com/en-us/121668",
		Anchors: of("6c61dac3a2def031506be036d2a6fe401994fbd13df9c8d466599274c446ec98")},
	{CA: "e-commerce monitoring", Program: "Chrome", IssuedAfter: at("2024-06-30T23:59:59Z"), BySCT: true, Effective: at("2024-07-01T00:00:00Z"), Description: "Chrome distrusts new GLOBALTRUST certificates", Link: "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto",
		Anchors: of("9a296a5182d1d451a2e37f439b74daafa267523329f90f9a0d2007c334e23c9a")},
	{CA: "e-commerce monitoring", Program: "Chrome", Effective: at("2025-07-09T00:00:00Z"), Description: "removed from the Chrome Root Store", Link: "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto",
		Anchors: of("9a296a5182d1d451a2e37f439b74daafa267523329f90f9a0d2007c334e23c9a")},
	{CA: "e-commerce monitoring", Program: "Mozilla", IssuedAfter: at("2024-06-30T00:00:00Z"), Effective: at("2024-07-09T00:00:00Z"), Description: "Firefox 128 distrusts new GLOBALTRUST certificates", Link: "https://bugzilla.mozilla.org/show_bug.cgi?id=1901080",
		Anchors: of("9a296a5182d1d451a2e37f439b74daafa267523329f90f9a0d2007c334e23c9a")},
	{CA: "e-commerce monitoring", Program: "Mozilla", Effective: at("2026-05-19T00:00:00Z"), Description: "removed in Firefox 151", Link: "https://bugzilla.mozilla.org/show_bug.cgi?id=2020164",
		Anchors: of("9a296a5182d1d451a2e37f439b74daafa267523329f90f9a0d2007c334e23c9a")},
	{CA: "e-commerce monitoring", Program: "Apple", IssuedAfter: at("2024-06-30T23:59:59Z"), Effective: at("2024-07-01T00:00:00Z"), Description: "Apple distrusts new GLOBALTRUST certificates", Link: "https://support.apple.com/en-us/121668",
		Anchors: of("9a296a5182d1d451a2e37f439b74daafa267523329f90f9a0d2007c334e23c9a")},
	{CA: "ComSign", Program: "Apple", IssuedAfter: at("2024-06-30T23:59:59Z"), Effective: at("2024-07-01T00:00:00Z"), Description: "Apple distrusts new ComSign certificates", Link: "https://support.apple.com/en-us/121668",
		Anchors: of("2605875afcc176b2d66dd66a995d7f8d5ebb86ce120d0e7e9e7c6ef294a27d4c")},
	{CA: "Camerfirma", Program: "Apple", IssuedAfter: at("2024-11-15T23:59:59Z"), Effective: at("2024-11-16T00:00:00Z"), Description: "Apple distrusts new Camerfirma certificates", Link: "https://support.apple.com/en-us/121668",
		Anchors: of("063e4afac491dfd332f3089b8542e94617d893d7fe944e10a7937ee29d9693c0", "136335439334a7698016a0d324de72284e079d7b5220bb8fbd747816eebebaca")},
	{CA: "Root age", Program: "Mozilla", Effective: at("2025-05-27T00:00:00Z"), Description: "Firefox 139 no longer trusts roots with keys from before 2006", Link: "https://wiki.mozilla.org/CA/Root_CA_Lifecycles",
		Anchors: of("16af57a9f676b0ab126095aa5ebadef22ab31119d644ac95cd4b93dbf3f26aeb", "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4", "c3846bf24b9e93ca64274c0ec67c1ecc5e024ffcacd2d74019350e81fe546ae4", "1465fa205397b876faa6f0a9958e5590e40fcc7faa4fb7c2c8677521fb5fb658", "cecddc905099d8dadfc5b1d209b737cbe2c18cfb2c10c0ff0bcf0d3286fc1aa2", "ebd41040e4bb3ec742c9e381d31ef2a41a48b6685c96e7cef3c1df6cd4331c99")},
	{CA: "Root age", Program: "Mozilla", Effective: at("2026-05-19T00:00:00Z"), Description: "Firefox 151 no longer trusts roots with keys from 2006 and 2007", Link: "https://wiki.mozilla.org/CA/Root_CA_Lifecycles",
		Anchors: of("eaa962c4fa4a6bafebe415196d351ccd888d4f53f3fa8ae6d7c466a94e6042bb", "62dd0be9b9f50a163ea0f8e75c053b1eca57ea55c8688f647c6881f2c8357b95", "4200f5043ac8590ebb527d209ed1503029fbcbd41ca1b506ec27f15ade7dac69", "f1c1b50ae5a20dd8030ec9f6bc24823dd367b5255759b4e71b61fce9f7375d73", "3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c", "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161", "7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf", "85a0dd7dd720adb7ff05f83d542b209dc7ff4528f7d677b18389fea5e5c49e86", "18f1fc7f205df8adddeb7fe007dd57e3af375a9c4d8d73546bf4f1fed1e18d35", "0c2cd63df7806fa399ede809116b575bf87989f06518f9808c860503178baf66", "e3b6a2db2ed7ce48842f7ac53241c7b71d54144bfb40c11f3f1d0b42f5eea12d", "dd6936fe21f8f077c123a1a521c12224f72255b73e03a7260693e8a24b0fa389")},
	{CA: "Izenpe", Program: "Mozilla", IssuedAfter: at("2026-04-15T23:59:59Z"), Effective: at("2026-05-19T00:00:00Z"), Description: "Firefox 151 distrusts new Izenpe certificates (root age)", Link: "https://wiki.mozilla.org/CA/Root_CA_Lifecycles",
		Anchors: of("2530cc8e98321502bad96f9b1fba1b099e2d299e0f4548bb914f363bc0d4531f")},
	{CA: "Atos", Program: "Mozilla", Effective: at("2026-08-18T00:00:00Z"), Description: "Firefox 154 no longer trusts it for websites", Link: "https://bugzilla.mozilla.org/show_bug.cgi?id=2017374",
		Anchors: of("f356bea244b7a91eb35d53ca9ad7864ace018e2d35d5f8f96ddf68a6f41aa474")},
	{CA: "Root age", Program: "Mozilla", Effective: at("2027-04-15T00:00:00Z"), Description: "Mozilla plans to stop trusting roots with keys from 2008 and 2009 for websites", Link: "https://wiki.mozilla.org/CA/Root_CA_Lifecycles",
		Anchors: of("1793927a0614549789adce2f8f34f7f0b66d0f3ae3a3b84d21ec15dbba4fadc7", "52f0e1c4e58ec629291b60317f074671b85d7ea80d5b07273463534b32b40234", "4ff460d54b9c86dabfbcfc5712e0400d2bed3fbc4d4fbdaa86e06adcd2a9ad7a", "e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2", "bfd88fe1101c41ae3e801bf8be56350ee9bad1a6b9bd515edc5c6d5b8711ac44", "fd73dad31c644ff1b43bef0ccdda96710b9cd9875eca7e31707af3e96d522bbd", "91e2f5788d5810eba7ba58737de1548a8ecacd014598bc0b143e041b17052552", "5c58468d55f58e497e743982d2b50010b6d165374acf83a7d4a32db768c4408e", "ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab5573894179b93fa", "6c61dac3a2def031506be036d2a6fe401994fbd13df9c8d466599274c446ec98", "cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b", "04048028bf1f2864d48f9ad4d83294366a828856553f3b14303f90147f5d40ef", "513b2cecb810d4cde5dd85391adfc6c2dd60d87bb736d2b521484aa47a0ebef6", "3c5f81fea5fab82c64bfa2eaecafcde8e077fc8620a7cae537163df36edbf378", "568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5", "45140b3247eb9cc8c5b4f0d7b53091f73292089e6e5a63e2749dd3aca9198eda", "2ce1cb0bf9d2f9e102993fbe215152c3b2dd0cabde1c68e5319b839154dbb7f5", "49e7a442acf0ea6287050054b52564b650e4f49e42e348d6aa38e039e957b1c1", "eec5496b988ce98625b934092eec2908bed0b0f316c2d4730c84eaf1f3d34881")},
	{CA: "Root age", Program: "Chrome", Effective: at("2025-04-24T00:00:00Z"), Description: "removed from the Chrome Root Store", Link: "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto",
		Anchors: of("ebd41040e4bb3ec742c9e381d31ef2a41a48b6685c96e7cef3c1df6cd4331c99", "16af57a9f676b0ab126095aa5ebadef22ab31119d644ac95cd4b93dbf3f26aeb", "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4", "c3846bf24b9e93ca64274c0ec67c1ecc5e024ffcacd2d74019350e81fe546ae4", "1465fa205397b876faa6f0a9958e5590e40fcc7faa4fb7c2c8677521fb5fb658", "cecddc905099d8dadfc5b1d209b737cbe2c18cfb2c10c0ff0bcf0d3286fc1aa2", "4200f5043ac8590ebb527d209ed1503029fbcbd41ca1b506ec27f15ade7dac69", "18f1fc7f205df8adddeb7fe007dd57e3af375a9c4d8d73546bf4f1fed1e18d35", "8a866fd1b276b57e578e921c65828a2bed58e9f2f288054134b7f1f4bfc9cc74", "bfd88fe1101c41ae3e801bf8be56350ee9bad1a6b9bd515edc5c6d5b8711ac44", "bf0feefb9e3a581ad5f9e9db7589985743d261085c4d314f6f5d7259aa421612", "30d0895a9a448a262091635522d1f52010b5867acae12c78ef958fd4f4389f2f", "a040929a02ce53b4acf4f2ffc6981ce4496f755e6d45fe0b2a692bcd52523f36", "44b545aa8a25e65a73ca15dc27fc36d24c1cb9953a066539b11582dc487b4833", "125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f", "bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3")},
	{CA: "Root age", Program: "Chrome", Effective: at("2026-04-14T00:00:00Z"), Description: "removed from the Chrome Root Store", Link: "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto",
		Anchors: of("4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161", "7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf", "3e9099b5015e8f486c00bcea9d111ee721faba355a89bcf1df69561e3dc6325c", "85a0dd7dd720adb7ff05f83d542b209dc7ff4528f7d677b18389fea5e5c49e86", "62dd0be9b9f50a163ea0f8e75c053b1eca57ea55c8688f647c6881f2c8357b95", "dd6936fe21f8f077c123a1a521c12224f72255b73e03a7260693e8a24b0fa389", "f1c1b50ae5a20dd8030ec9f6bc24823dd367b5255759b4e71b61fce9f7375d73", "eaa962c4fa4a6bafebe415196d351ccd888d4f53f3fa8ae6d7c466a94e6042bb", "e3b6a2db2ed7ce48842f7ac53241c7b71d54144bfb40c11f3f1d0b42f5eea12d", "97552015f5ddfc3c8788c006944555408894450084f100867086bc1a2bb58dc8", "945bbc825ea554f489d1fd51a73ddf2ea624ac7019a05205225c22a78ccfa8b4", "55903859c8c0c3ebb8759ece4e2557225ff5758bbd38ebd48276601e1bd58097")},
	{CA: "Atos", Program: "Chrome", Effective: at("2026-06-20T00:00:00Z"), Description: "removed from the Chrome Root Store", Link: "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto",
		Anchors: of("f356bea244b7a91eb35d53ca9ad7864ace018e2d35d5f8f96ddf68a6f41aa474")},
}

// programRoots are the public key hashes of the roots each program trusts
// for websites today: Chrome's root_store.textproto as of 9 October 2026
// (100 anchors) and the server-auth roots of Firefox 155's certdata.txt
// (121). A chain that also leads to one of them is anchored there by that
// program, whatever old root the server sends a cross-sign from. Apple
// and Microsoft publish no such list, so their events judge the anchor
// alone.
var programRoots = map[string]map[string]bool{
	"Chrome":  keySet(chromeRootKeys),
	"Mozilla": keySet(mozillaRootKeys),
}

const chromeRootKeys = `
	05570ae6eb0fceb4210e6db79486b7094caf200401e149b6677441b5f25e449b 06600b94c0318bb6967f0c7787cc8a1032a179c4e95e3c5760b32e290f7fec9b
	07e854f26a7cbd389927aa041bfef1b6cd21dd143818ad947dc655a9e587fe88 08b3a6335fce5ef48f8f0e543986c07fd18a3b1226129f61864bbd5bdd1f1cc9
	0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3 0e05e9bb23869eb689dc56839dcec475a3ae75fa6b50bc5a4978360cbe673323
	0e8bb18bbeefb381be21bfc1a206d317298462ad104855f04a0542699708d3d4 1255cabe8152fa64df942f7a47417e29f96c1ce11bf8c84ecbe2815cc1280810
	149f2ee63b9a5e5803240a770dc991fc2e3445e62831c245a49bc4f1f738ff9c 15eed339594b304f8cf847b477371d8d6fec61f4db2b01af589e7c53b35cae4c
	1bf00d5c8f13c094dd17e00504cf0888850f12fd067fa1f92c0fdbf60b86e321 1ef64625daa2e5d433d7449ae31a200d1025e0012a8fecfa70932f8b599b75dd
	2021917e98263945c859c43f1d73cb4139053c414fa03ca3bc7ee88614298f3b 2541e53ba5b3b07acbe7097ac4a03e040c11cf7a6d4a67cb213d558b50167a06
	25d4913cf587097414d29d26f6c1b1942cd6d64eaf45d0fcf81526adba96d324 2a8f2d8af0eb123898f74c866ac3fa669054e23c17bc7a95bd0234192dc635d0
	2bcf553a66f570900ddd32ba6dfe1ecc06c9182d662dc1b60e1f7b767c2bdd54 2fc5667a4b9a2678ed6ac6ad25465fcbf6094bfcd9504097c7a8fa47ade5e888
	3329bfa13b6007ab5fc3713f0acb289426e2fbc99cc5c110a914b139571600b6 3380709af3b096be3cc2a40548142c0a520028db09e2cb77ae2206616ab6cbb4
	348767cdad3bdd28b2b8dd5351aec30c68cec5cd69d276df3827dbc4f5806464 35f53ce1264611e03340fe37e1ec7d4cc986c5613dca70fd04aa44545f2daf28
	36abc32656acfc645c61b71613c4bf21c787f5cabbee48348d58597803d7abc9 376a1a7082a593dccc20d561d119e9ab8d30f11cc321d0a37fa41f0df284e01c
	3b0d73b4be4a854adc3e51d7ef9fa48aefbb2cdd824d67bdc7d7d09a2abc2d43 3f93f3fcf79d225d213eef6a4a3f5885cf84fe3d7a7a3c11553517688c0e2100
	42431627ea76cc78697f915e3455b1b2ec82ff2f6380ee6423ef3c0840b7e631 453b74809b69019627f2f843001db5950cdd1d45371053e7f3dfdbc3714113c6
	47487900a1beb9ee08ccbc1116a8ec55f454b638994319f051b984023ced6423 4a49edbd2f8f8230bd5592b313573fe1c172a45fa98011cc1eddbb36ade3fce5
	55e00be277ceb0545299f24fd9f877e2acf32852db43ffcd29bca74b39b4c9fa 5628872e245fe66148b80badeac9c40f6252e642fa9595aece4b3e8a58b8fd46
	5955ae291574a931342cf7450e16652ede1e0fb3097e1571dfac11c915601564 59df317bfa9f4f0ab7ca514d7772296aa2c765b87664d08b96e57399e364729c
	5c41a73ab2c35dfcd771f6fd6e3e8fac9b469d386cadda56a95b646eb48cca34 603f76f28c9feba83ec751edb66c8d7523ea40fe49fe74427629f50dabbcf55a
	608963c78c455e6e34b072468ace0956cff18d34643f9f305b7162fa181979fc 6106c0e3a0a299831875127bd7d3cc1859803d511cac11eb6e0840dd166fc10e
	616167201433aea6c8e5e3070afcaf6749188f814bd1abb179ae8dad3abf26ec 681dc482c296c8402c6ebb20e68309a3bc846523ae34b984a84ee697a3312db7
	682747f8ba621b87cdd3bc295ed5cabce722a1c0c0363d1d68b38928d2787f1e 693c9aa6b245b3b0261637750863eadb6c248a16e52d6f4bc90c86bbf32d7042
	6a97b51c8219e93e5dec64bad5806cdeb0f8355be47e757010b702456e01aafd 6e364b6133deefdcbb21273c5f445a20afbc05038d5b021c0c2153039016345b
	702116ccd8bf23e16466f0e0dba0ed6a239a9c1cd6a8f5a66b39af3595020385 706bb1017c855c59169bad5c1781cf597f12d2cad2f63d1a4aa37493800ffb80
	762195c225586ee6c0237456e2107dc54f1efc21f61a792ebd515913cce68332 786ffa578618c3b9a311175e50816f4dda0605c3869f296ebc5943bf09f4e904
	79caaf5347e6e4a94c8e78a98496fc74020f809ede13f220fab6104c8ded329f 7cd67c248f69d83fc2f9bb01dcb1f7ad67a363d046043796d0984c3a231f6bb0
	7e0ead76bb6819dc2f54511a84354f6e8b307b9dd82058ea6c004f01d9dda5df 7f4296fc5b6a4e3b35d3c369623e364ab1af381d8fa7121533c9d6c633ea2461
	808d68b3fab4884a5f971ace7d10550d7a95a163774f3ec36afffb213fbe4c74 82b5f84daf47a59c7ab521e4982aefa40a53406a3aec26039efa6b2e0e7244c1
	871a9194f4eed5b312ff40c84c1d524aed2f778bbff25f138cf81f680a7adc67 8bb593a93be1d0e8a822bb887c547890c3e706aad2dab76254f97fb36b82fc26
	8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782 8d767764b3cbda08929d072a22a561f4dcdd1bc57d3cbddc948c47d2b47f9122
	8e8046ec4cac015a507ce0d2d0154a4b40e8e42b3165cfa546571435112d17e5 952c2039c0243eb515dd73d83fc3643184874feb0862a9837731ed9b4742e17a
	9847e5653e5e9e847516e5cb818606aa7544a19be67fd7366d506988e8d84347 9a52ff6a3cb6e353a08567e0dc9c395b300d60a22292ab8c18c1656b2983ae90
	9d37e4a989eab3882d116052fc8b58446702cb593726e4604c3795940c7103e2 a02fafa192c8cb81cb1341554f9c05b71cca2a890b0d1298d683647c961efbdf
	a246b822f96cfecc155156e5476957845492acf32187ec8a2ef12d89618d711d a320f4d534d7be97c1ae8dd0499735bc895c323add2d388bfccf662c23d7f99a
	aa2630a7b617b04d0a294bab7a8caaa5016e6dbe604837a83a85719fab667eb5 ac76f63a46e761b5acc3259705c920cb7f0563d248d8d180f934af68099a15f9
	ae7f962cb9e6a7dbf7b833fb18fa9b71a89175df949c232b6a9ef7cb3df2bbfc b03d87b056d08cc9d4e675ef19ca83ab53532168a8258598be72e6d85c7dd7c1
	b0b56335468561f5bb9fa12d801784a633a572705d34f32b643445dfa8b005d1 b2f7298b52bf2c3cac4ddfe72de4d682ac58957595982f2b62301af597c699c5
	b94c198300cec5c057ad0727b70bbe91816992256439a7b32f4598119dda9c97 b964e141d3a55cae180ea6a1a8d4a297de26f11833c673569d196fb533a98710
	c2b3c31a4a29850aa8f3cf472a1169ff71b416579f6a4482ec7744b83df988ac c444b5b66ce5d71e1b5e40f27385c95cbfd24a05b56f70cac0992f0f50c3379c
	c784333d20bcd742b9fdc3236f4e509b8937070e73067e254dd3bf9c45bf4dde c942262c0c7c0a95bb152b71c42556ddbe9a04fa8378373550d2b7ce27d952a3
	cbad7b1d384849df0946b7ee8e7f5f7ce3aed876fda7bc9d30d8b16f29ff2c53 ceb19411c65052c757f941eb826c96941e4d08d096c7db7e7ea3c4f8c13f1a13
	d1c45377ebdcd618cd1651dc2e02c21d751e5aa9fcd1b3431ff6ecf6a31348fa d439dd80f1e3bc5c9e5f13e8bff7a8887df9dc1c3e19d76af70c8f8d985eef22
	dd5ed1c090f9f448061baa94a6bb11017544e9eefaa20cc714ce6c633f5dc629 de7b6932e9c44582ce0de07abdab7eea90c75d6d2a07331df57bd5cb88553d13
	e04a022ce32f4ccf2c7f6046287b828a32a909f5e751447f83fd2c71f6fd8173 e06647e52610160c3e83c42d22e39aa8750c584d6c24afaed54a61164742000a
	e753cdd9f13413c7ca9cda82962f8c0ce5ed13d1657312954af5267eb2cb7c79 e7ca91bbfbb18788057b3a8070446ea5291160194102f7dcc3b9848c63cb9cd5
	eab0de5a46419010b01b2d55553fc111aa82b43d9395edfeaeaa8c76e6ad1995 ebc978ae0dd9e5822d6b19652596f620c93d7caefa952191cb050a632ca9005f
	eca0f181402ce7a8652b31b4d036df247e3a30b7f41a50d91ec4f90b006b43a1 f1c6ba670cfc88e4df52973cae420f0a089dd474144fe5806c420064e1591229
	f3438e23b3ce532522facf307923f58fd18608e9ba7addc30e952b43c49616c3 f4632e58701c0bd7dafc7e3831355ec433fc13777de286683e8ec50964df0452
	f7ca77a610e3d42447240692dbd57cfd13cf042acd2062e6a62b87b9ed81c1a7 f7ecded5c66047d28ed6466b543c40e0743abe81d109254dcf845d4c2c7853c5
	fbe3018031f9586bcbf41727e417b7d1c45c2f47f93be372a17b96b50757d5a2 fc784300ec8df4d3d1bad763835182918d52a9ff0238bdf695a1cd9bdb98321c
	fd371bea9755ff60c8828c849b8e5215de532d61b009855fa0ad630d90eef82e ff342fb6c4c8bd30a4706f73489539f19e6e48cc05f46254654f6610dbc540e9
`

const mozillaRootKeys = `
	05570ae6eb0fceb4210e6db79486b7094caf200401e149b6677441b5f25e449b 06600b94c0318bb6967f0c7787cc8a1032a179c4e95e3c5760b32e290f7fec9b
	07a2904d4bff9604ea1331ae990e9ffe331232e69ecb8a08cd49d8e34757db41 07e854f26a7cbd389927aa041bfef1b6cd21dd143818ad947dc655a9e587fe88
	08b3a6335fce5ef48f8f0e543986c07fd18a3b1226129f61864bbd5bdd1f1cc9 0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3
	0e05e9bb23869eb689dc56839dcec475a3ae75fa6b50bc5a4978360cbe673323 0e8bb18bbeefb381be21bfc1a206d317298462ad104855f04a0542699708d3d4
	1255cabe8152fa64df942f7a47417e29f96c1ce11bf8c84ecbe2815cc1280810 149f2ee63b9a5e5803240a770dc991fc2e3445e62831c245a49bc4f1f738ff9c
	15eed339594b304f8cf847b477371d8d6fec61f4db2b01af589e7c53b35cae4c 1bf00d5c8f13c094dd17e00504cf0888850f12fd067fa1f92c0fdbf60b86e321
	1ef64625daa2e5d433d7449ae31a200d1025e0012a8fecfa70932f8b599b75dd 2021917e98263945c859c43f1d73cb4139053c414fa03ca3bc7ee88614298f3b
	2541e53ba5b3b07acbe7097ac4a03e040c11cf7a6d4a67cb213d558b50167a06 25d4913cf587097414d29d26f6c1b1942cd6d64eaf45d0fcf81526adba96d324
	294679e0f97ffd474f19567b36382394e1b4960e030975e66353452034a3c5ea 2a8f2d8af0eb123898f74c866ac3fa669054e23c17bc7a95bd0234192dc635d0
	2b071c59a0a0ae76b0eadb2bad23bad4580b69c3601b630c2eaf0613afa83f92 2bcf553a66f570900ddd32ba6dfe1ecc06c9182d662dc1b60e1f7b767c2bdd54
	2fc5667a4b9a2678ed6ac6ad25465fcbf6094bfcd9504097c7a8fa47ade5e888 3329bfa13b6007ab5fc3713f0acb289426e2fbc99cc5c110a914b139571600b6
	3380709af3b096be3cc2a40548142c0a520028db09e2cb77ae2206616ab6cbb4 348767cdad3bdd28b2b8dd5351aec30c68cec5cd69d276df3827dbc4f5806464
	35f53ce1264611e03340fe37e1ec7d4cc986c5613dca70fd04aa44545f2daf28 36abc32656acfc645c61b71613c4bf21c787f5cabbee48348d58597803d7abc9
	376a1a7082a593dccc20d561d119e9ab8d30f11cc321d0a37fa41f0df284e01c 3b0d73b4be4a854adc3e51d7ef9fa48aefbb2cdd824d67bdc7d7d09a2abc2d43
	3f93f3fcf79d225d213eef6a4a3f5885cf84fe3d7a7a3c11553517688c0e2100 4179edd981ef747477b49626408af43daa2ca7ab7f9e082c1060f84096774348
	42431627ea76cc78697f915e3455b1b2ec82ff2f6380ee6423ef3c0840b7e631 453b74809b69019627f2f843001db5950cdd1d45371053e7f3dfdbc3714113c6
	47487900a1beb9ee08ccbc1116a8ec55f454b638994319f051b984023ced6423 4a49edbd2f8f8230bd5592b313573fe1c172a45fa98011cc1eddbb36ade3fce5
	4c821d7d89adf08c1e951c92b841b4a3c18261b9ce426f337cc0e3805499ba0e 50cc86ba96db3263c79a43ead07553d9f56659e6907e72d8c026637a1cdc85dc
	536cfdae8a6257bf14266c43285958d0f9b937e3068e2a215374170133a9ffcc 55e00be277ceb0545299f24fd9f877e2acf32852db43ffcd29bca74b39b4c9fa
	5628872e245fe66148b80badeac9c40f6252e642fa9595aece4b3e8a58b8fd46 581cc15821169694c39c2991b53e93ab945a42b076661774c2ecf38a3323acea
	58dd61feb36ea7d258724371709149cb121337864cacb2d0999ad20739d06477 5955ae291574a931342cf7450e16652ede1e0fb3097e1571dfac11c915601564
	59df317bfa9f4f0ab7ca514d7772296aa2c765b87664d08b96e57399e364729c 5c41a73ab2c35dfcd771f6fd6e3e8fac9b469d386cadda56a95b646eb48cca34
	603f76f28c9feba83ec751edb66c8d7523ea40fe49fe74427629f50dabbcf55a 608963c78c455e6e34b072468ace0956cff18d34643f9f305b7162fa181979fc
	6106c0e3a0a299831875127bd7d3cc1859803d511cac11eb6e0840dd166fc10e 616167201433aea6c8e5e3070afcaf6749188f814bd1abb179ae8dad3abf26ec
	681dc482c296c8402c6ebb20e68309a3bc846523ae34b984a84ee697a3312db7 682747f8ba621b87cdd3bc295ed5cabce722a1c0c0363d1d68b38928d2787f1e
	693c9aa6b245b3b0261637750863eadb6c248a16e52d6f4bc90c86bbf32d7042 6a97b51c8219e93e5dec64bad5806cdeb0f8355be47e757010b702456e01aafd
	6b3b57e9ec88d1bb3d01637ff33c7698b3c9758255e9f01ea9178f3e7f3b2b52 6e364b6133deefdcbb21273c5f445a20afbc05038d5b021c0c2153039016345b
	702116ccd8bf23e16466f0e0dba0ed6a239a9c1cd6a8f5a66b39af3595020385 706bb1017c855c59169bad5c1781cf597f12d2cad2f63d1a4aa37493800ffb80
	762195c225586ee6c0237456e2107dc54f1efc21f61a792ebd515913cce68332 786ffa578618c3b9a311175e50816f4dda0605c3869f296ebc5943bf09f4e904
	79caaf5347e6e4a94c8e78a98496fc74020f809ede13f220fab6104c8ded329f 7cd67c248f69d83fc2f9bb01dcb1f7ad67a363d046043796d0984c3a231f6bb0
	7e0ead76bb6819dc2f54511a84354f6e8b307b9dd82058ea6c004f01d9dda5df 7f4296fc5b6a4e3b35d3c369623e364ab1af381d8fa7121533c9d6c633ea2461
	808d68b3fab4884a5f971ace7d10550d7a95a163774f3ec36afffb213fbe4c74 82b5f84daf47a59c7ab521e4982aefa40a53406a3aec26039efa6b2e0e7244c1
	8685ad850f7f56cd16943bcb70b434e7356e1b8bdc613406e2ea8de46092b636 86a68f050034126a540d39db2c5f917ef66a94fb9619fa1ecd827cea46ba0cb0
	871a9194f4eed5b312ff40c84c1d524aed2f778bbff25f138cf81f680a7adc67 8bb593a93be1d0e8a822bb887c547890c3e706aad2dab76254f97fb36b82fc26
	8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782 8d767764b3cbda08929d072a22a561f4dcdd1bc57d3cbddc948c47d2b47f9122
	8e8046ec4cac015a507ce0d2d0154a4b40e8e42b3165cfa546571435112d17e5 92c46879626ef2cc1ecea50c72fb5e385844095f21cbf3b283cb82e6b9fc6a58
	952c2039c0243eb515dd73d83fc3643184874feb0862a9837731ed9b4742e17a 9847e5653e5e9e847516e5cb818606aa7544a19be67fd7366d506988e8d84347
	9a52ff6a3cb6e353a08567e0dc9c395b300d60a22292ab8c18c1656b2983ae90 9d37e4a989eab3882d116052fc8b58446702cb593726e4604c3795940c7103e2
	a02fafa192c8cb81cb1341554f9c05b71cca2a890b0d1298d683647c961efbdf a246b822f96cfecc155156e5476957845492acf32187ec8a2ef12d89618d711d
	a320f4d534d7be97c1ae8dd0499735bc895c323add2d388bfccf662c23d7f99a aa2630a7b617b04d0a294bab7a8caaa5016e6dbe604837a83a85719fab667eb5
	ac76f63a46e761b5acc3259705c920cb7f0563d248d8d180f934af68099a15f9 ae7f962cb9e6a7dbf7b833fb18fa9b71a89175df949c232b6a9ef7cb3df2bbfc
	b03d87b056d08cc9d4e675ef19ca83ab53532168a8258598be72e6d85c7dd7c1 b0b56335468561f5bb9fa12d801784a633a572705d34f32b643445dfa8b005d1
	b2f7298b52bf2c3cac4ddfe72de4d682ac58957595982f2b62301af597c699c5 b7408b4d2be0238ba37004dd34e276c6019bd2f24c9db7d4980f5f6c359a4bcc
	b94c198300cec5c057ad0727b70bbe91816992256439a7b32f4598119dda9c97 b964e141d3a55cae180ea6a1a8d4a297de26f11833c673569d196fb533a98710
	bb52086d0639e8db332775ac8f4e8435d92ceb00f4e24f28fc0eabe240772e80 c2b3c31a4a29850aa8f3cf472a1169ff71b416579f6a4482ec7744b83df988ac
	c444b5b66ce5d71e1b5e40f27385c95cbfd24a05b56f70cac0992f0f50c3379c c784333d20bcd742b9fdc3236f4e509b8937070e73067e254dd3bf9c45bf4dde
	c942262c0c7c0a95bb152b71c42556ddbe9a04fa8378373550d2b7ce27d952a3 cbad7b1d384849df0946b7ee8e7f5f7ce3aed876fda7bc9d30d8b16f29ff2c53
	cc94a5a0319ff77a4ccadd821c4c59674e44d52816cbd1dfe2c761370ad4d21c ceb19411c65052c757f941eb826c96941e4d08d096c7db7e7ea3c4f8c13f1a13
	d1c45377ebdcd618cd1651dc2e02c21d751e5aa9fcd1b3431ff6ecf6a31348fa d439dd80f1e3bc5c9e5f13e8bff7a8887df9dc1c3e19d76af70c8f8d985eef22
	dd5ed1c090f9f448061baa94a6bb11017544e9eefaa20cc714ce6c633f5dc629 de7b6932e9c44582ce0de07abdab7eea90c75d6d2a07331df57bd5cb88553d13
	e04a022ce32f4ccf2c7f6046287b828a32a909f5e751447f83fd2c71f6fd8173 e06647e52610160c3e83c42d22e39aa8750c584d6c24afaed54a61164742000a
	e753cdd9f13413c7ca9cda82962f8c0ce5ed13d1657312954af5267eb2cb7c79 e7ca91bbfbb18788057b3a8070446ea5291160194102f7dcc3b9848c63cb9cd5
	eab0de5a46419010b01b2d55553fc111aa82b43d9395edfeaeaa8c76e6ad1995 eabc185c4e82d942b1a5978ba3c0181487d6b3b9974e5c49f72f6d0bd9637150
	ebc55f21e88d49ede81c0075ab08b3c73b81f0f33e37d7641a1d01b6e602dc9d ebc978ae0dd9e5822d6b19652596f620c93d7caefa952191cb050a632ca9005f
	eca0f181402ce7a8652b31b4d036df247e3a30b7f41a50d91ec4f90b006b43a1 f0011f92fcf9be36c7a5b36e7bc862ab20e94ef36fea8a561db0a8d7750c1f51
	f0e0b6fbe8b74d4f82d8ed8f8bd6a3d083dc19db3d2cedb1061ccb76d848ee7d f1c6ba670cfc88e4df52973cae420f0a089dd474144fe5806c420064e1591229
	f3438e23b3ce532522facf307923f58fd18608e9ba7addc30e952b43c49616c3 f4632e58701c0bd7dafc7e3831355ec433fc13777de286683e8ec50964df0452
	f48badd7df6a06690d0ae31373b12855f8dedb14517f362a313101cc98cc6b35 f7ca77a610e3d42447240692dbd57cfd13cf042acd2062e6a62b87b9ed81c1a7
	f7ecded5c66047d28ed6466b543c40e0743abe81d109254dcf845d4c2c7853c5 fbe3018031f9586bcbf41727e417b7d1c45c2f47f93be372a17b96b50757d5a2
	fc784300ec8df4d3d1bad763835182918d52a9ff0238bdf695a1cd9bdb98321c fd371bea9755ff60c8828c849b8e5215de532d61b009855fa0ad630d90eef82e
	ff342fb6c4c8bd30a4706f73489539f19e6e48cc05f46254654f6610dbc540e9
`

func keySet(s string) map[string]bool {
	m := map[string]bool{}
	for _, k := range strings.Fields(s) {
		m[k] = true
	}
	return m
}

// at parses a table timestamp.
func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// of returns the anchors with these certificate fingerprints.
func of(fps ...string) []Anchor {
	out := make([]Anchor, 0, len(fps))
	for _, fp := range fps {
		a, ok := distrustAnchors[fp]
		if !ok {
			panic("distrust table: no anchor " + fp)
		}
		out = append(out, a)
	}
	return out
}
