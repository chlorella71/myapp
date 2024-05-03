package bitcamp.myapp.security;

import bitcamp.myapp.vo.Member;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Data
@RequiredArgsConstructor
public class MemberUserDetails extends Member implements UserDetails {

  private final Member member;

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    ArrayList<GrantedAuthority> authorities = new ArrayList<>();
    //ArrayList는 Collection 인터페이스를 구현함
    authorities.add(() -> "ROLE_USER");
    return authorities;
  }

  @Override
  public String getUsername() {
    return this.member.getEmail();
  }

  @Override
  public String getPassword() {
    return this.member.getPassword();
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}
