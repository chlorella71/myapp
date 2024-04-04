-- DDL(Data Definition Language)

drop table if exists boards restrict;
drop table if exists board_files restrict;
drop table if exists assignments restrict;
drop table if exists members restrict;
--drop table boards;

create table boards(
  board_no int not null,
--  board_no int primary key auto_increment,
  title varchar(255) not null,
  content mediumtext not null,
--  writer varchar(30) not null,
  writer int not null,
  category int not null,
  created_date datetime null default now()
);

alter table boards
  add constraint primary key (board_no),
  modify column board_no int not null auto_increment;

create table board_files(
  file_no int not null,
  file_path varchar(255) not null,
  board_no int not null
);

alter table board_files
  add constraint primary key (file_no),
  modify column file_no int not null auto_increment,
  add constraint board_files_fk foreign key (board_no) references boards(board_no);
--  보통 프라이머리 키는 이름을 안붙이지만 그 외(유니크 키 등)는 이름을 붙여 사용함

---- 문자열은 더블코테이션이 아닌 싱글 코테이션''
---- 명령문의 끝은 세미콜론;
--insert into boards(title,content,writer, category) values('제목1', '내용1', '홍길동', 1);
--insert into boards(title,content,writer, category) values('제목2', '내용2', '임꺽정', 1);
--insert into boards(title,content,writer, category) values('제목3', '내용3', '유관순', 2);
--insert into boards(title,content,writer, category) values('제목4', '내용4', '안중근', 2);
--insert into boards(title,content,writer, category) values('제목5', '내용5', '윤봉길', 2);

-- 셀렉트 문 : 값을 확인할 때 사용
--select * from boards;
---- 보드의 모든 값을 확인
--
--select *
--from boards
--where board_no = 3;

--insert into boards(
--  board_no,
--  title,
--  content,
--  writer)
--  values(1, '제목1', '내용1', '홍길동');
--insert into boards(board_no,title,content,writer)
--  values(2, '제목2', '내용2', '임꺽정');
--insert into boards(board_no,title,content,writer)
--  values(3, '제목3', '내용3', '유관순');
--insert into boards(board_no,title,content,writer)
--  values(4, '제목4', '내용4', '안중근');
--insert into boards(board_no,title,content,writer)
--  values(5, '제목5', '내용5', '윤봉길');

-- sql(structure quary language) : 구조화된 질의,질문 언어
-- dbms에게 형식에 갖춰서 의뢰, 질의할때 사용하는 문법, 언어
-- dbms서버에게 보내고 dbms가 응답(쿼리언어)
-- mysql프로그램은 dbms에게 명령어를 전달하고 서버가 보낸 것을 그대로 출력할 뿐임

--update boards set
--  title='okok',
--  content='nono',
--  writer='hoho'
--where board_no = 3;
--
--delete from boards where board_no=3;

--drop table assignment;

create table assignments(
assignment_no int not null,
--  assignment_no int primary key auto_increment,
  title varchar(255) not null,
  content mediumtext not null,
  deadline date not null
);

alter table assignments
  add constraint primary key (assignment_no),
  modify column assignment_no int not null auto_increment;
--insert into assignments(
--  assignment_no,
--  title,
--  content,
--  deadline)
--  values(1, '제목1', '내용1', '2024-05-22');
--insert into assignments(assignment_no,title,content,deadline)
--  values(2, '제목2', '내용2', '2024-05-22');
--insert into assignments(assignment_no,title,content,deadline)
--  values(3, '제목3', '내용3', '2024-05-22');
--insert into assignments(assignment_no,title,content,deadline)
--  values(4, '제목4', '내용4', '2024-05-22');
--insert into assignments(assignment_no,title,content,deadline)
--  values(5, '제목5', '내용5', '2024-05-22');

--drop table members;

create table members(
  member_no int not null,
--  member_no int primary key auto_increment,
  email varchar(255) not null,
  name varchar(255) not null,
  password varchar(100) not null,
  photo varchar(255) null,
  created_date datetime null default now()
  );

alter table members
  add constraint primary key (member_no),
  modify column member_no int not null auto_increment,
  add constraint members_uk unique key (email);

--insert into members(member_no,email,name,password)
--  values(1,'aa@bit.com','홍일동',sha2('aa',256));
--insert into members(member_no,email,name,password)
--  values(2,'bb@bit.com','홍이동',sha2('bb',256));
--insert into members(member_no,email,name,password)
--  values(3,'cc@bit.com','홍삼동',sha2('cc',256));
--insert into members(member_no,email,name,password)
--  values(4,'dd@bit.com','홍사동',sha2('dd',256));
--insert into members(member_no,email,name,password)
--  values(5,'ee@bit.com','홍오동',sha2('ee',256));
--
--desc boards;
--
--alter table boards
--  add column category int not null;
--
--update boards set category=1;

alter table boards
  add constraint boards_fk foreign key (writer) references members(member_no);