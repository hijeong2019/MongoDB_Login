// Express 기본 모듈
var express = require("express")
    , http = require("http")
    , path = require('path');

// Express 미들웨어
var bodyParser = require('body-parser'),
    static = require('serve-static'),
    cookieParser = require('cookie-parser');

var expressErrorHandler = require('express-error-handler');
var expressSession = require('express-session');
var mongoose = require('mongoose');

var crypto = require('crypto');

//express 객체 생성
var app = express();

app.set('port', process.env.PORT || 3000);

//bodyParser를 사용해 application.x-www-form-urlencoded 파싱
app.use(bodyParser.urlencoded({extended : false}));

//bodyParser를 사용해 application/json 파싱
app.use(bodyParser.json());

//public 폴더를 static으로 오픈
app.use('/public',static(path.join(__dirname, 'public')));

app.use(cookieParser());
app.use(expressSession({
    secret:'my key',
    resave : true,
    saveUninitialized : true
}));

var db;
var UserSchema;
var UserModel;
function connectDB(){
    var databaseUrl = 'mongodb://localhost:27017/local' //데이터베이스 연결 정보
    console.log('데이터베이스 연결 시도');
    mongoose.Promise = global.Promise;
    mongoose.connect(databaseUrl);
    db = mongoose.connection;

    db.on('error', console.error.bind(console,'mongoose connection error'));
    db.on('open',function(){
        console.log('데이터베이스에 연결됨 : '+databaseUrl);

        createUserSchema(); //user 스키마, 모델 객체 생성
    });

    //연결 끊어졌을 때 5초 뒤 재연결
    db.on('disconnected', function(){
        console.log('연결이 끊어졌습니다. 5초 뒤 재연결합니다.');
        setInterval(connectDB, 5000);
    });
}

function createUserSchema(){ //user스키마, 모델 객체 생성
	// 스키마 정의
	// password를 hashed_password로 변경, 각 칼럼에 default 속성 모두 추가, salt 속성 추가
	UserSchema = mongoose.Schema({
	    id: {type: String, required: true, unique: true, 'default':''},
	    hashed_password: {type: String, required: true, 'default':''},
	    salt: {type:String, required:true},
	    name: {type: String, index: 'hashed', 'default':''},
	    age: {type: Number, 'default': -1},
	    created_at: {type: Date, index: {unique: false}, 'default': Date.now},
	    updated_at: {type: Date, index: {unique: false}, 'default': Date.now}
	});
	
	// password를 virtual 메소드로 정의 : MongoDB에 저장되지 않는 가상 속성임. 
    // 특정 속성을 지정하고 set, get 메소드를 정의함
	UserSchema
	  .virtual('password')
	  .set(function(password) {
	    this._password = password;
	    this.salt = this.makeSalt();
	    this.hashed_password = this.encryptPassword(password);
	    console.log('virtual password의 set 호출됨 : ' + this.hashed_password);
	  })
	  .get(function() {
           console.log('virtual password의 get 호출됨.');
           return this._password;
      });
	
	// 스키마에 모델 인스턴스에서 사용할 수 있는 메소드 추가
	// 비밀번호 암호화 메소드
	UserSchema.method('encryptPassword', function(plainText, inSalt) {
		if (inSalt) {
			return crypto.createHmac('sha1', inSalt).update(plainText).digest('hex');
		} else {
			return crypto.createHmac('sha1', this.salt).update(plainText).digest('hex');
		}
	});
	
	// salt 값 만들기 메소드
	UserSchema.method('makeSalt', function() {
		return Math.round((new Date().valueOf() * Math.random())) + '';
	});
	
	// 인증 메소드 - 입력된 비밀번호와 비교 (true/false 리턴)
	UserSchema.method('authenticate', function(plainText, inSalt, hashed_password) {
		if (inSalt) {
			console.log('authenticate 호출됨 : %s -> %s : %s', plainText, this.encryptPassword(plainText, inSalt), hashed_password);
			return this.encryptPassword(plainText, inSalt) === hashed_password;
		} else {
			console.log('authenticate 호출됨 : %s -> %s : %s', plainText, this.encryptPassword(plainText), this.hashed_password);
			return this.encryptPassword(plainText) === this.hashed_password;
		}
	});

	// 값이 유효한지 확인하는 함수 정의
	var validatePresenceOf = function(value) {
		return value && value.length;
	};
		
	// 저장 시의 트리거 함수 정의 (password 필드가 유효하지 않으면 에러 발생)
	UserSchema.pre('save', function(next) {
		if (!this.isNew) return next();

		if (!validatePresenceOf(this.password)) {
			next(new Error('유효하지 않은 password 필드입니다.'));
		} else {
			next();
		}
	})
	
	// 필수 속성에 대한 유효성 확인 (길이값 체크)
	UserSchema.path('id').validate(function (id) {
		return id.length;
	}, 'id 칼럼의 값이 없습니다.');
	
	UserSchema.path('name').validate(function (name) {
		return name.length;
	}, 'name 칼럼의 값이 없습니다.');
	
	UserSchema.path('hashed_password').validate(function (hashed_password) {
		return hashed_password.length;
	}, 'hashed_password 칼럼의 값이 없습니다.');
	
    
    UserSchema.static('findById', function(id, callback){
        return this.find({id:id}, callback);
    });
    
    UserSchema.static('findAll',function(callback){
        return this.find({}, callback);
    });
    console.log('UserSchema 정의함');
    
    //UserModel 모델 정의
    UserModel = mongoose.model("users2", UserSchema);
    console.log('UserModel 정의함');
}


//라우터 객체 참조
var router = express.Router();

//로그인 라우팅 함수
router.post('/process/login', function(req,res){
    console.log('/process/login 호출');

    var paramId = req.body.id || req.query.id;
    var paramPassword = req.body.password || req.query.password;

    if(db){
        authUser(db, paramId, paramPassword, function(err, docs){
            if(err) {throw err};

            if(docs){
                console.dir(docs);
                var username = docs[0].name;
                res.writeHead('200',{'Content-type':'text/html;charset=utf8'});
                res.write('<h1>로그인 성공</h1>');
                res.write('<div>사용자 아이디 : '+paramId+'</div>');
                res.write('<div>사용자 비번 : '+paramPassword+'</div>');
                res.write("<br><br><a href='/public/login.html'>다시 로그인하기<a>");
                res.end();
            }else{
                res.writeHead('200',{'Content-type':'text/html;charset=utf8'});
                res.write('<h1>로그인 실패</h1>');
                res.write('<div> 아이디, 비번 다시확인</div>');
                res.write("<br><br><a href='/public/login.html'>다시 로그인하기<a>");
                res.end();
            }
        });
    }else{
        res.writeHead('200',{'Content-type':'text/html;charset=utf8'});
        res.write('<h1>데이터베이스 연결 실패</h1>');
        res.end();
    }
})

//사용자 추가 라우팅 함수 - 클라이언트에서 보내온 데이터를 이용해 데이터베이스에 추가
router.route('/process/adduser').post(function(req,res){
    console.log('/process/adduser 호출');

    var paramId = req.body.id || req.query.id;
    var paramPassword = req.body.password || req.query.password;
    var paramName = req.body.name || req.query.name;

    console.log('요청 파라미터 : '+paramId+', '+paramPassword+', '+paramName);

    if(db){
        addUser(db, paramId, paramPassword, paramName, function(err, addedUser){
            if(err) {throw err;}

            if(addedUser){
                console.dir(addedUser);

                res.writeHead('200',{'Content-type':'text/html;charset=utf8'});
                res.write('<h1>사용자 추가 성공</h1>');
                res.end();
            }else{
                res.writeHead('200',{'Content-type':'text/html;charset=utf8'});
                res.write('<h1>사용자 추가 실패</h1>');
                res.end();
            }
        });
    }else{
        res.writeHead('200',{'Content-type':'text/html;charset=utf8'});
        res.write('<h1>데이터베이스 연결 실패</h1>');
        res.end();
    }
});

//사용자 리스트 함수
router.route('/process/listuser').post(function(req,res){
    console.log('/process/listuser 호출됨');

    //데이터베이스 객체 초기화된경우, 모델객체의 findAll 메소드 호출
    if(db){
        //1.모든 사용자 검색
        UserModel.findAll(function(err,results){
            
            if(err){ //오류 발생 시 클라이언트로 오류 전송
                console.err('사용자 리스트 조회 중 오류 : '+err.stack);

                res.writeHead('200',{'Content-type':'text/html;charset=utf8'});
                res.write('<h1>사용자 리스트 조회 중 오류 발생</h1>');
                res.write('<p>'+err.stack+'</p>');
                res.end();
                return;
            }

            if(results){ //결과 객체 있으면 리스트 전송
                console.dir(results);

                res.writeHead('200',{'Content-type':'text/html;charset=utf8'});
                res.write('<title>사용자 리스트</title>')
                res.write('<h1>사용자 리스트 조회</h1>');
                res.write('<div><ul>');

                    for(var i=0; i<results.length; i++){
                        var curId = results[i]._doc.id;
                        var curName = results[i]._doc.name;
                        res.write('<li>#' + i + ' : ' + curId + ' , ' + curName + '</li>');
                    }

                res.write('</ul></div>');
                res.end();
            }else{ //결과 객체 없으면 실패 전송
                res.writeHead('200',{'Content-type':'text/html;charset=utf8'});
                res.write('<h1>사용자 리스트 조회 실패</h1>');
                res.end();
            }
        });
    }else{ //데이터베이스 객체가 초기회되지 않았을 때 실패 전송
        res.writeHead('200',{'Content-type':'text/html;charset=utf8'});
        res.write('<h1>데이터베이스 연결 실패</h1>');
        res.end();
    }
});

//라우터 객체 등록
app.use('/',router);

//사용자 인증 함수
var authUser = function(db, id, password, callback){
    console.log('authuser 호출'+id+', '+password);

    //1.아이디 사용해 검색
    UserModel.findById(id,function(err, results){
        if(err){
            callback(err, null);
            return;
        }
        console.log('아이디[%s]로 사용자 검색 결과',id);
        console.dir(results);

        if(results.length > 0){
            console.log('아이디와 알치하는 사용자 찾음');

            //2.비번 확인
            var user = new UserModel({id:id});
            var authenticated = user.authenticate(password, results[0]._doc.salt, results[0]._doc.hashed_password);

            if(authenticated){
                console.log('비번 일치함');
                callback(null, results);
            }else{
                console.log('비번 일치하지 않음');
                callback(null,null);
            }
        }else{
            console.log('아이디 일치하는 사용자 없음');
            callback(null,null);
        }
    });
};

//사용자 추가 함수
var addUser = function(db, id, password, name, callback){
    console.log('addUser 호출됨 : '+id+', '+password+', '+name);
    
    //UserModel 인스턴스 생성
    var user = new UserModel({"id":id,"password":password,"name":name});

    //save()로 저장
    user.save(function(err){
        if(err){
            callback(err,null);
            return;
        }
        console.log('사용자 데이터 추가함');
        callback(null,user);
    });
};



var errorHandler = expressErrorHandler({
    static:{
        '404':'./public/404.html'
    }
});

app.use(expressErrorHandler.httpError(404));
app.use(errorHandler);

//서버 시작
http.createServer(app).listen(app.get('port'),function(){
    console.log('express start'+app.get('port'));

    connectDB();
})