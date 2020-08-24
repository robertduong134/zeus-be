package vn.com.vetc.zeus.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import vn.com.vetc.zeus.common.AppException;
import vn.com.vetc.zeus.users.Users;
import vn.com.vetc.zeus.users.UsersRepository;

import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	@Autowired
	UsersRepository usersRepository;

	@Override
	@Transactional
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		//only authencation in here
		Optional<Users> users = usersRepository.findByUsernameAndStatus(username, Users.Status.ACTIVE.toString());

		users.orElseThrow(() -> new AppException("User not found!"));

		return UserPrinciple.from(users.get());
	}
}