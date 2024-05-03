package bitcamp.myapp.controller;

import bitcamp.myapp.dao.MemberDao;
import bitcamp.myapp.security.MemberUserDetails;
import bitcamp.myapp.service.MemberService;
import bitcamp.myapp.vo.Member;
import java.util.Map;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RequiredArgsConstructor
@Controller
@RequestMapping("/auth")
public class AuthController {

  private static final Log log = LogFactory.getLog(AuthController.class);
  private final MemberService memberService;

  @GetMapping("form")
  public void form(@CookieValue(required = false) String email, Model model) {
    model.addAttribute("email", email);
  }


//  @PostMapping("login")
//  public String login(
//      String email,
//      String password,
//      String saveEmail,
//      HttpServletResponse response,
//      HttpSession session) throws Exception {
//
//    log.debug("login() 호출됨!");
//
//    if (saveEmail != null) {
//      Cookie cookie = new Cookie("email", email);
//      cookie.setMaxAge(60 * 60 * 24 * 7);
//      response.addCookie(cookie);
//    } else {
//      Cookie cookie = new Cookie("email", "");
//      cookie.setMaxAge(0);
//      response.addCookie(cookie);
//    }
//
//      Member member = memberService.get(email, password);
//    if (member != null) {
//    session.setAttribute("loginUser", member);
//    }
//    return "auth/login";
//  }

  @GetMapping("logout")
  public String logout(HttpSession session) throws Exception {
    session.invalidate();
    return "redirect:/index.html";
  }

  @RequestMapping("loginSuccess")
  public String loginSuccess(
      HttpServletResponse response,
      String saveEmail,
      @AuthenticationPrincipal MemberUserDetails principal,
      HttpSession session
  ) throws Exception {
    log.debug("로그인 성공!!!");
    log.debug(principal);
    log.debug(saveEmail);

    if (saveEmail != null) {
      Cookie cookie = new Cookie("email", principal.getUsername());
      cookie.setMaxAge(60 * 60 * 24 * 7);
      response.addCookie(cookie);
    } else {
      Cookie cookie = new Cookie("email", "");
      cookie.setMaxAge(0);
      response.addCookie(cookie);
    }
    session.setAttribute("loginUser", principal.getMember());

    return "redirect:/index.html";
  }


}
