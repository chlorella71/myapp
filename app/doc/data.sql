-- members 테이블 데이터

insert into members(member_no,email,name,password,created_date)
  values(101,'user1@test.com','user1',sha2('1111',256),'2024-1-1');
insert into members(member_no,email,name,password,created_date)
  values(102,'user2@test.com','user2',sha2('1111',256),'2024-2-2');
insert into members(member_no,email,name,password,created_date)
  values(103,'user3@test.com','user3',sha2('1111',256),'2024-3-3');
insert into members(member_no,email,name,password,created_date)
  values(104,'uesr4@test.com','user4',sha2('1111',256),'2024-4-4');
insert into members(member_no,email,name,password,created_date)
  values(105,'uesr5@test.com','user5',sha2('1111',256),'2024-5-5');


-- boards 테이블 데이터
--insert into boards(title,content,writer, category) values('제목1', '내용1', '홍길동', 1);
--insert into boards(title,content,writer, category) values('제목2', '내용2', '임꺽정', 1);
--insert into boards(title,content,writer, category) values('제목3', '내용3', '유관순', 2);
--insert into boards(title,content,writer, category) values('제목4', '내용4', '안중근', 2);
--insert into boards(title,content,writer, category) values('제목5', '내용5', '윤봉길', 2);

insert into boards(
  board_no,
  title,
  content,
  writer,
  category)
  values(1, '제목1', '내용1', 101, 1);
insert into boards(board_no,title,content,writer, category)
  values(2, '제목2', '내용2', 102, 1);
insert into boards(board_no,title,content,writer, category)
  values(3, '제목3', '내용3', 102, 2);
insert into boards(board_no,title,content,writer, category)
  values(4, '제목4', '내용4', 104, 2);
insert into boards(board_no,title,content,writer, category)
  values(5, '제목5', '내용5', 104, 1);
insert into boards(board_no,title,content,writer, category)
  values(6, '제목6', '내용5', 101, 1),
  (7, '제목7', '내용5', 102, 1),
  (8, '제목8', '내용5', 103, 1),
  (9, '제목9', '내용5', 104, 1),
  (10, '제목10', '내용5', 101, 1),
  (11, '제목11', '내용5', 102, 1),
  (12, '제목12', '내용5', 103, 1),
  (13, '제목13', '내용5', 104, 1),
  (14, '제목14', '내용5', 101, 1),
  (15, '제목15', '내용5', 102, 1),
  (16, '제목16', '내용5', 103, 1),
  (17, '제목17', '내용5', 104, 1),
  (18, '제목18', '내용5', 101, 1),
  (19, '제목19', '내용5', 102, 1),
  (20, '제목20', '내용5', 103, 2),
  (21, '제목21', '내용5', 104, 2),
  (22, '제목22', '내용5', 101, 2),
  (23, '제목23', '내용5', 102, 2),
  (24, '제목24', '내용5', 103, 2),
  (25, '제목25', '내용5', 104, 2);

--  board_files 테이블 데이터
insert into board_files(file_no,file_path,board_no) values
  (1, 'a1.gif', 1), (2, 'a2.gif', 1), (3, 'a3.gif', 1),
  (4, 'b1.gif', 2), (5, 'b2.gif', 2),
  (6, 'c1.gif', 3), (7, 'c2.gif', 3), (8, 'c3.gif', 4), (9, 'c4.gif', 4),
  (10, 'd1.gif', 5);


-- assignments 테이블 데이터
insert into assignments(
  assignment_no,
  title,
  content,
  deadline)
  values(1, '제목1', '내용1', '2024-05-22');
insert into assignments(assignment_no,title,content,deadline)
  values(2, '제목2', '내용2', '2024-05-22');
insert into assignments(assignment_no,title,content,deadline)
  values(3, '제목3', '내용3', '2024-05-22');
insert into assignments(assignment_no,title,content,deadline)
  values(4, '제목4', '내용4', '2024-05-22');
insert into assignments(assignment_no,title,content,deadline)
  values(5, '제목5', '내용5', '2024-05-22');

