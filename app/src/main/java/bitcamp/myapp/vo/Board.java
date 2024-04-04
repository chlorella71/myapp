package bitcamp.myapp.vo;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import lombok.Data;

//@NoArgsConstructor
@Data
public class Board implements Serializable {

  private static final long serialVersionUID = 100L;

  private int category;
  private int no;
  private String title;
  private String content;
//  private String writer;
  private Member writer;
  private Date createdDate;
  private List<AttachedFile> fileList;
  private int fileCount;
}
