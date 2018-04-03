open Suave
open Secure
open Encodings
open System.Security.Claims
open Suave.Successful
open Suave.Filters
open Suave.Operators

[<EntryPoint>]
let main _ =
  
  // http://localhost:8083/suave/audience2/sample1 requires no authentication
  // http://localhost:8083/suave/audience2/sample2 requires admin authentication

  // Values obtained by calling the AuthorizationServer's audience registration API
  let jwtConfig = {
    Issuer = "http://localhost:8083/suave"
    ClientId = "ada9263885c440869fb484fe354de13d"
    SecurityKey = KeyStore.securityKey <| Base64String.fromString "0RWyzyttDmJtiaYkG9rph5cqxCTI8YAOsR7stq-P_5o"
  }

  let sample1 = 
    path "/audience2/sample1" 
    >=> 
    OK "Sample 1"


  // Claim Seq -> Async<AuthorizationResult>
  let authorizeSuperUser (claims : Claim seq) =
    let isSuperUser (c : Claim) =
      c.Type = ClaimTypes.Role && c.Value = "SuperUser"
    match claims |> Seq.tryFind isSuperUser with
    | Some _ -> Authorized |> async.Return
    | None -> UnAuthorized "User is not a Super User" |> async.Return

  let authorize = jwtAuthorize jwtConfig

  let sample2 = 
    path "/audience2/sample2" 
    >=>
    authorize authorizeSuperUser (OK "Sample 2") 
      

  let config = 
    { defaultConfig 
        with bindings = [HttpBinding.createSimple HTTP "127.0.0.1" 8085]}

  let app = choose [sample1;sample2]

  startWebServer config app
  0