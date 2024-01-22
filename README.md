# SpringJwtSecuriy

The flow to understand the jwt security code:

1)JwtTokenUtilService
=>This class is for generating the token and extracting the info like userName from our token.
Or can take some fields of the token.

2)JwtRequestFilter
=>In this class we will validate the jwt or token for every api or request.

3)JwtUserDetailsService
=>When user tries to login then this class is to check whether his credentials are valid or not.

And the flow of remaining classes we can understand.
