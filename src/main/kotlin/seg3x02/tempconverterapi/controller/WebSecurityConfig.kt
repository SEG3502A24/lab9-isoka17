package seg3x02.tempconverterapi.controller

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class WebSecurityConfig {

    @Bean
    @Throws(Exception::class)
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .authorizeHttpRequests { auth -> auth
                    .requestMatchers("/temperature-converter/**").hasRole("USER")
                    .requestMatchers("/error").permitAll()
                    .anyRequest().authenticated()
            }
            .httpBasic(Customizer.withDefaults())
            .logout(Customizer.withDefaults())
        return http.build()
    }

    @Bean
    fun userDetailsService(): UserDetailsService {
        val user1 = createUser("user1", "pass1")
        val user2 = createUser("user2", "pass2")
        return InMemoryUserDetailsManager(user1, user2)
    }

    @Bean
    fun passwordEncoder(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder()
    }

    private fun createUser(username: String, password: String): UserDetails {
        return User.withUsername(username)
            .password(passwordEncoder().encode(password))
            .roles("USER")
            .build()
    }

}

