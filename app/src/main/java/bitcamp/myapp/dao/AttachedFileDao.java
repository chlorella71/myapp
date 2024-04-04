package bitcamp.myapp.dao;

import bitcamp.myapp.vo.AttachedFile;
import bitcamp.myapp.vo.Board;
import java.util.List;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AttachedFileDao {

  void add(AttachedFile file);

  int addAll(List<AttachedFile> files);
// 몇개를 등록했는지 알 수 있도록 int값 리턴

  int delete(int no);

  int deleteAll(int boardNo);

  List<AttachedFile> findAllByBoardNo(int boardNo);

  AttachedFile findByNo(int no);

  // 첨부파일은 조회하거나 변경하도록 다루지는 않음.
  // 오직 등록, 삭제, 목록만
//  Board findBy(int no);
//
//  int update(Board board);

}
