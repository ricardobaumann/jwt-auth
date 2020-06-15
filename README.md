## Jwt auth library

This library intends to enable custom authentication and authorization support on http services. 

### Usage

#### Token services
For token issue services, since there is no need to configure routes, the library exposes a class `JwtTokenService` that can injected and used to generate tokens. 

So, include the `@EnableCustomJwt` on your configuration or main class
````
    @EnableCustomJwt
    public class MyServiceConfiguration {

    } 
````
Then, on your service class, inject and use the `CreateTokenUseCase` managed object. 
````
    public class SecurityService {
        
        private final JwtTokenService jwtTokenService; //Autowired or constructor injecting
    }
````
And do not forget the jwt configurations
````
    jwt:
      secretKey: "<somelongsecretkey>"
      validityInMillis: 60000
````
#### Resource Services
For resource services, include the `@EnableCustomJwt` on your configuration or main class, just like on the previous example:
````
    @EnableCustomJwt
    public class MyServiceConfiguration {

    } 
````
Then, on your routes security config, you need to include the `AuthFilterConfigurer` configuration object. For example:
````    
    @Configuration
    @EnableCustomJwt
    public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
        private final JwtFilterConfigurer jwtFilterConfigurer;
    
        public SecurityConfig(JwtFilterConfigurer jwtFilterConfigurer) {
            this.jwtFilterConfigurer = jwtFilterConfigurer;
        }
    
        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
        }
    
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.httpBasic().disable()
                    .csrf().disable()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .authorizeRequests()
                    .antMatchers("/auth").permitAll() //in case you have an open route for auth
                    .anyRequest().authenticated()
                    .and().apply(jwtFilterConfigurer);
        }
    }

````


Alternatively, if all routes on your resource service need to be secured, you can just annotate your configuration or main class with `@EnableCakeDefaultSecurity`:
````
    @EnableCakeDefaultSecurity
    public class MyServiceConfiguration {

    } 
````
This way, you have all routes secured by default.
And again, do not forget the jwt settings 
````
    jwt:
      secretKey: "<somelongsecretkey>>"
      validityInMillis: 60000
````

To inject the authenticated user on your controllers with all the custom information:
````
    @GetMapping("/test")
    public String test(@AuthenticationPrincipal CakeUserDetails userDetails) {
        return userDetails.getId();
    }
````
