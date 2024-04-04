//package bitcamp.myapp.config;
//
//import java.nio.charset.StandardCharsets;
//import org.apache.commons.logging.Log;
//import org.apache.commons.logging.LogFactory;
//import org.springframework.context.ApplicationContext;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.ComponentScan;
//import org.springframework.transaction.annotation.EnableTransactionManagement;
//import org.springframework.web.multipart.MultipartResolver;
//import org.springframework.web.multipart.support.StandardServletMultipartResolver;
//import org.springframework.web.servlet.ViewResolver;
//import org.springframework.web.servlet.view.InternalResourceViewResolver;
//import org.thymeleaf.ITemplateEngine;
//import org.thymeleaf.spring5.ISpringTemplateEngine;
//import org.thymeleaf.spring5.SpringTemplateEngine;
//import org.thymeleaf.spring5.templateresolver.SpringResourceTemplateResolver;
//import org.thymeleaf.spring5.view.ThymeleafViewResolver;
//import org.thymeleaf.templatemode.TemplateMode;
//import org.thymeleaf.templateresolver.ITemplateResolver;
//
////@ComponentScan(value = {"bitcamp.myapp.controller"})
//public class AppConfig {
//  private final Log log = LogFactory.getLog(this.getClass());
//
//  public AppConfig() {
//    log.debug("생성자 호출됨!");
//  }
//
//  @Bean
//  public MultipartResolver multipartResolver() {
//    return new StandardServletMultipartResolver();
//  }
//
////  @Bean
////  public ViewResolver viewResolver() {
////    InternalResourceViewResolver viewResolver = new InternalResourceViewResolver("/WEB-INF/jsp/", ".jsp");
////    viewResolver.setPrefix("/WEB-INF/jsp/");
//////    viewResolver.setSuffix(".jsp");
////    viewResolver.setViewNames("*.jsp");
////    viewResolver.setOrder(1);
////    return viewResolver;
////  }
////
////  @Bean
////  public ThymeleafViewResolver thymeleafViewResolver(ISpringTemplateEngine springTemplateEngine){
////    ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
////    viewResolver.setTemplateEngine(springTemplateEngine);
////    // NOTE 'order' and 'viewNames' are optional
////    viewResolver.setViewNames(new String[] {"*.html", "*.xhtml", "*"});
////    viewResolver.setCharacterEncoding(StandardCharsets.UTF_8.name());
////    viewResolver.setOrder(2);
////    return viewResolver;
////  }
////
////  @Bean
////  public SpringResourceTemplateResolver templateResolver(ApplicationContext applicationContext){
////    // SpringResourceTemplateResolver automatically integrates with Spring's own
////    // resource resolution infrastructure, which is highly recommended.
////    SpringResourceTemplateResolver templateResolver = new SpringResourceTemplateResolver();
////    templateResolver.setApplicationContext(applicationContext);
////    templateResolver.setPrefix("/WEB-INF/templates/");
////    templateResolver.setSuffix(".html");
////    // HTML is the default value, added here for the sake of clarity.
////    templateResolver.setTemplateMode(TemplateMode.HTML);
////    // Template cache is true by default. Set to false if you want
////    // templates to be automatically updated when modified.
////
////    // (개발하는 동안에는 수시로 HTML 템플릿 파일을 변경하기 때문에...)
////    // HTML 템플릿을 Thymeleaf 엔진이 사용할 수 있도록
////    // 특정 형식에 맞춰 컴파일 해 둘 것인가?
////    // => 컴파일? 어떤 형식의 데이터를 다른 형식의 데이터로 바꾸는 것도 컴파일이다.
////    // => cacheable = true
////    //    템플릿 파일을 한 번 컴파일하면 캐시에 보관해 둔다.
////    //    실행할 때마다 매번 컴파일하지 않기 때문에 실행 속도가 빠르다.
////    //    단 템플릿 파일을 변경하더라도 다시 컴파일 하지 않는다.
////    //    다시 컴파일하려면 서버를 다시 실행해야 한다.
////    //    그래서 개발하는 동안에는 캐시를 사용하지 않는 것이 좋다.
////    //    왜? 개발하는 동안 템플릿 파일의 내용을 자주 바꾸기 때문이다.
////    // => cacheable = false
////    //    템플릿 파일의 컴파일 결과를 캐시에 보관하지 않는다.
////    //    실행할 때 마다 템플릿 파일을 컴파일 하는 것이 좋다.
////    //    컴파일한 것을 보관해두면 템플릿 파일을 변경하더라도 다시 컴파일하지 않는다.
////    //    왜? 템플릿 파일을 변경할 때마다 서버를 다시 실행해야 하기 때문이다.
////    // => 개발이 완료된 다음에는 템플릿 파일을 컴파일한 결과를 보관해 두는 것이
////    //    실행 속도를 높인다.
////    templateResolver.setCacheable(false);
////    return templateResolver;
////  }
////
////  @Bean
////  public SpringTemplateEngine templateEngine(ITemplateResolver templateResolver){
////    // SpringTemplateEngine automatically applies SpringStandardDialect and
////    // enables Spring's own MessageSource message resolution mechanisms.
////    SpringTemplateEngine templateEngine = new SpringTemplateEngine();
////    templateEngine.setTemplateResolver(templateResolver);
////    // Enabling the SpringEL compiler with Spring 4.2.4 or newer can
////    // speed up execution in most scenarios, but might be incompatible
////    // with specific cases when expressions in one template are reused
////    // across different data types, so this flag is "false" by default
////    // for safer backwards compatibility.
////    templateEngine.setEnableSpringELCompiler(true);
////    return templateEngine;
////  }
//}
