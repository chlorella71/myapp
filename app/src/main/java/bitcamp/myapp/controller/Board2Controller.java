package bitcamp.myapp.controller;

import bitcamp.myapp.annotation.LoginUser;
import bitcamp.myapp.service.Board2Service;
import bitcamp.myapp.service.StorageService;
import bitcamp.myapp.vo.AttachedFile;
import bitcamp.myapp.vo.Board;
import bitcamp.myapp.vo.Member;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.multipart.MultipartFile;

@RequiredArgsConstructor
@Controller
@RequestMapping("/board2")
@SessionAttributes("attachedFiles")
public class Board2Controller {

  private static final Log log = LogFactory.getLog(Board2Controller.class);
  private final Board2Service boardService;
  private final StorageService storageService;
  private String uploadDir = "board/";

  @Value("${ncp.ss.bucketname}")
  private String bucketName;

  @GetMapping("form")
  public void form() throws Exception {
  }

  @PostMapping("add")
  public String add(
      Board board,
      @LoginUser Member loginUser,
//      MultipartFile[] files,
      HttpSession session,
      SessionStatus sessionStatus) throws Exception {

    log.debug(loginUser);

    board.setWriter(loginUser);

    List<AttachedFile> attachedFiles = (List<AttachedFile>) session.getAttribute("attachedFiles");
    if (attachedFiles == null) {
      attachedFiles = new ArrayList<>();
    }

    for (int i = attachedFiles.size() - 1; i >= 0; i--) {
      AttachedFile attachedFile = attachedFiles.get(i);
      if (board.getContent().indexOf(attachedFile.getFilePath()) == -1) {
        storageService.delete(this.bucketName, this.uploadDir, attachedFile.getFilePath());
        log.debug(String.format("%s 파일 삭제!", attachedFile.getFilePath()));
        attachedFiles.remove(i);
      }
    }
    if (attachedFiles.size() > 0) {
      board.setFileList(attachedFiles);
    }

    boardService.add(board);

    sessionStatus.setComplete();

    return "redirect:list";
  }

  @GetMapping("list")
  public void list(
      @RequestParam(defaultValue = "1") int pageNo,
      @RequestParam(defaultValue = "3") int pageSize,
      Model model) throws Exception {

    if (pageSize < 3 || pageSize > 20) {
      pageSize = 3;
    }

    if (pageNo < 1) {
      pageNo = 1;
    }

    int numOfRecord = boardService.countAll();
    int numOfPage = numOfRecord / pageSize + ((numOfRecord % pageSize) > 0 ? 1 : 0);

    if (pageNo > numOfPage) {
      pageNo = numOfPage;
    }

    model.addAttribute("list", boardService.list(pageNo, pageSize));
    model.addAttribute("pageNo", pageNo);
    model.addAttribute("pageSize", pageSize);
    model.addAttribute("numOfPage", numOfPage);
  }

  @GetMapping("view")
  public void view(int no, Model model) throws Exception {
    Board board = boardService.get(no);
    if (board == null) {
      throw new Exception("번호가 유효하지 않습니다.");
    }

    model.addAttribute("board", board);
  }

  @PostMapping("update")
  public String update(
      Board board,
      @LoginUser Member loginUser,
      HttpSession session,
      SessionStatus sessionStatus) throws Exception {

    Board old = boardService.get(board.getNo());
    old.setFileList(boardService.getAttachedFiles(board.getNo()));
    log.debug(String.format("%s", old.getFileList()));
    if (old == null) {
      throw new Exception("번호가 유효하지 않습니다.");

    } else if (old.getWriter().getNo() != loginUser.getNo()) {
      throw new Exception("권한이 없습니다.");
    }

    List<AttachedFile> attachedFiles = (List<AttachedFile>) session.getAttribute("attachedFiles");
    if (attachedFiles == null) {
      attachedFiles = new ArrayList<>();
    }

    if (old.getFileList().size() > 0) {
      attachedFiles.addAll(old.getFileList());
    }
    if (attachedFiles != null) {

      for (int i = attachedFiles.size() - 1; i >= 0; i--) {
        AttachedFile attachedFile = attachedFiles.get(i);
        if (!board.getContent().contains(attachedFile.getFilePath())) {
          storageService.delete(this.bucketName, this.uploadDir, attachedFile.getFilePath());
          log.debug(String.format("%s 파일 삭제!", attachedFile.getFilePath()));
          attachedFiles.remove(i);
        }
      }

      if (attachedFiles.size() > 0) {
        board.setFileList(attachedFiles);
      }
    }
    boardService.update(board);

    sessionStatus.setComplete();

    return "redirect:list";

//    ArrayList<AttachedFile> attachedFiles = new ArrayList<>();
//    for (MultipartFile file : files) {
//      if (file.getSize() == 0) {
//        continue;
//      }
//      String filename = storageService.upload(this.bucketName, this.uploadDir, file);
//      attachedFiles.add(AttachedFile.builder().filePath(filename).build());
//    }
//
//    if (attachedFiles.size() > 0) {
//      board.setFileList(attachedFiles);
//    }
//
//    // 네이버 스토리지에 저장된 이미지를 지우기 위함
//    List<AttachedFile> oldFiles = boardService.getAttachedFiles(board.getNo());
//
//    boardService.update(board);
//
//    for (AttachedFile file : oldFiles) {
//      storageService.delete(this.bucketName, this.uploadDir, file.getFilePath());
//    }
//
//    return "redirect:list";

  }

  @GetMapping("delete")
  public String delete(
      int no,
      @LoginUser Member loginUser) throws Exception {

    Board board = boardService.get(no);
    if (board == null) {
      throw new Exception("번호가 유효하지 않습니다.");

    } else if (board.getWriter().getNo() != loginUser.getNo()) {
      throw new Exception("권한이 없습니다.");
    }

    List<AttachedFile> files = boardService.getAttachedFiles(no);

    boardService.delete(no);

    for (AttachedFile file : files) {
      storageService.delete(this.bucketName, this.uploadDir, file.getFilePath());
    }

    return "redirect:list";
  }

  @GetMapping("file/delete")
  public String fileDelete(int no, @LoginUser Member loginUser) throws Exception {

    AttachedFile file = boardService.getAttachedFile(no);
    if (file == null) {
      throw new Exception("첨부파일 번호가 유효하지 않습니다.");
    }

    Member writer = boardService.get(file.getBoardNo()).getWriter();
    if (writer.getNo() != loginUser.getNo()) {
      throw new Exception("권한이 없습니다.");
    }

    boardService.deleteAttachedFile(no);

    storageService.delete(this.bucketName, this.uploadDir, file.getFilePath());

    return "redirect:../view?no=" + file.getBoardNo();
  }

  @PostMapping("file/upload")
  @ResponseBody
  public Object fileUpload(MultipartFile[] files, @LoginUser Member loginUser, HttpSession session, Model model)
      throws Exception {
    ArrayList<AttachedFile> attachedFiles = new ArrayList<>();

    if (loginUser == null) {
      return attachedFiles;
    }

    for (MultipartFile file : files) {
      if (file.getSize() == 0) {
        continue;
      }
      String filename = storageService.upload(this.bucketName, this.uploadDir, file);
      attachedFiles.add(AttachedFile.builder().filePath(filename).build());
    }

    model.addAttribute("attachedFiles", attachedFiles);

    return attachedFiles;
  }
}
