package ludmylla.api.rest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication
@EntityScan(basePackages = {"ludmylla.api.rest.model"})// Aponta o package model, para entityScan ler e criar tableas automáticas.
@ComponentScan(basePackages = {"ludmylla.*"}) // O spring vai ler e configurar tudo que começar com pacote.
@EnableJpaRepositories(basePackages = {"ludmylla.api.rest.repository"})
@EnableTransactionManagement // Habilita a gerencia de transação, evitar problemas a hora de salvar e etc.
@EnableWebMvc // Em spring pode trabalhar com rest, mvc.
@RestController // Para saber que é um projeto rest, e que os controlles vão retorna json.
@EnableAutoConfiguration // Spring vai configurar todo projeto, já vai deixar tudo pronto.
@EnableCaching //Habilita o cache para a aplicação
public class SpringrestapiApplication implements WebMvcConfigurer {
	
	public static void main(String[] args) {
		SpringApplication.run(SpringrestapiApplication.class, args);
		
		//System.out.println(new BCryptPasswordEncoder().encode("123"));
	}
	
	// Mapeamento global que refletem em todo sistema
	
	@Override
	public void addCorsMappings(CorsRegistry registry) {	
		registry.addMapping("/**")
		.allowedMethods("*")
		.allowedOrigins("GET","POST","PUT","DELETE","OPTIONS")
		.allowCredentials(false);

	}
	
	
}
