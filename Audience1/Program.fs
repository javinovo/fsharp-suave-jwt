open Suave
open Secure
open Encodings
open System.Security.Claims
open Suave.Successful
open Suave.Filters
open Suave.Operators

[<EntryPoint>]
let main _ =

  // http://localhost:8083/suave/audience1/sample1 requires authentication
  // http://localhost:8083/suave/audience1/sample2 requires admin authentication

  // Values obtained by calling the AuthorizationServer's audience registration API
  let jwtConfig = {
    Issuer = "http://localhost:8083/suave"
    ClientId = "7ff79ba3305c4e4f9d0ececeae70c78f"
    SecurityKey = KeyStore.securityKey <| Base64String.fromString "Op5EqjC70aLS2dx3gI0zADPIZGX2As6UEwjA4oyBjMo"
  }

  let sample1 = 
    path "/audience1/sample1" 
    >=> 
    jwtAuthenticate jwtConfig (OK "Sample 1")


  // Claim Seq -> Async<AuthorizationResult>
  let authorizeAdmin (claims : Claim seq) =
    let isAdmin (c : Claim) =
        c.Type = ClaimTypes.Role && c.Value = "Admin"
    match claims |> Seq.tryFind isAdmin with
    | Some _ -> Authorized |> async.Return
    | None -> UnAuthorized "User is not an admin" |> async.Return

  let sample2 = 
    path "/audience1/sample2" 
    >=> 
    jwtAuthorize jwtConfig authorizeAdmin (OK "Sample 2")


  let config = 
    { defaultConfig 
        with bindings = [HttpBinding.createSimple HTTP "127.0.0.1" 8084]}

  let app = choose [sample1;sample2]

  startWebServer config app
  0