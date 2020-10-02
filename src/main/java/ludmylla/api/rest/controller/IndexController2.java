package ludmylla.api.rest.controller;


import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import org.springframework.web.bind.annotation.RestController;

import ludmylla.api.rest.model.Usuario;
import ludmylla.api.rest.repository.UsuarioRepository;

@CrossOrigin(origins = "https://www.javaavancado.com.br/")
@RestController // Arquitetura REST
@RequestMapping(value = "/usuario2")
public class IndexController2 {
	
	@Autowired
	private UsuarioRepository usuarioRepository;
	
	
	@GetMapping(value = "/{id}/codigovenda/{venda}", produces = "application/json")
	public ResponseEntity<Usuario> relatorio(@PathVariable(value = "id") Long id,
			@PathVariable(value = "venda") Long venda) {	
		
		Optional<Usuario> usuario = usuarioRepository.findById(id);
		
		/* Retorno seria um relatorio */
		
		return new ResponseEntity<Usuario>(usuario.get(), HttpStatus.OK);
	}
	
	
	/* Serviço RESTfull */
	@GetMapping(value = "/{id}", produces = "application/json")
	public ResponseEntity<Usuario> init(@PathVariable(value = "id") Long id) {	
		
		Optional<Usuario> usuario = usuarioRepository.findById(id);
		
		return new ResponseEntity<Usuario>(usuario.get(), HttpStatus.OK);
	}
	
	@GetMapping(value = "/", produces = "application/json")
	public ResponseEntity<List<Usuario>> usuario(){
		
		List<Usuario> list = (List<Usuario>) usuarioRepository.findAll();
		
		return new ResponseEntity<List<Usuario>>(list, HttpStatus.OK);
	}
	
	@PostMapping(value = "/", produces = "application/json")
	public ResponseEntity<Usuario> cadastrar(@RequestBody Usuario usuario){
		
		// Na hora de salvar, automaticamente vamos pegar o telefones e relacionar ao usuario
		
		for (int pos = 0; pos < usuario.getTelefones().size(); pos++) {
			usuario.getTelefones().get(pos).setUsuario(usuario);
		}
		
		// Exemplo de fazer o for usando expressao lambdas
		// usuario.getTelefones().forEach(t -> t.setUsuario(usuario));
	
		
		Usuario usuarioSalvo = usuarioRepository.save(usuario);
		return new ResponseEntity<Usuario>(usuarioSalvo, HttpStatus.OK);
		
	}
	
	@PostMapping(value = "/{iduser}/idvenda/{idvenda}", produces = "application/json")
	public ResponseEntity<Usuario> cadastrarVenda(@PathVariable Long iduser, @PathVariable Long idvenda){
		
		//Usuario usuarioSalvo = usuarioRepository.save(usuario);
		return new ResponseEntity("id user: " + iduser+ " id venda: " +idvenda, HttpStatus.OK);
		
	}
	
	@PutMapping(value = "/", produces = "application/json")
	public ResponseEntity<Usuario> atualizar(@RequestBody Usuario usuario){
		
		for (int pos = 0; pos < usuario.getTelefones().size(); pos++) {
			usuario.getTelefones().get(pos).setUsuario(usuario);
		}
		
		Usuario usuarioUpdate = usuarioRepository.save(usuario);
		
		return new ResponseEntity<Usuario>(usuarioUpdate, HttpStatus.OK);
		
	}
	
	@DeleteMapping(value = "/{id}/venda", produces = "application/text")
	public String deleteVenda(@PathVariable("id") Long id) {
		
		usuarioRepository.deleteById(id);
		
		return "ok";
	}
	
	
	@DeleteMapping(value = "/{id}", produces = "application/text")
	public String delete(@PathVariable("id") Long id) {
		
		usuarioRepository.deleteById(id);
		
		return "ok";
	}
	


}
