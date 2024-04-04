package bitcamp.myapp.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor // Mybatis가 사용할 기본 생성자를 만들어야 한다.
@AllArgsConstructor
@Data
@Builder
public class AttachedFile {

  private int no;
  private String filePath;
  private int boardNo;
}
