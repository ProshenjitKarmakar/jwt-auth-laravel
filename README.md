
# JWT (JSON Web Token) Auth Installation in Laravel

Using JWT Auth we authorize all resquest and information Exchange.

### JSON Web Token structure
- Header
- Payload
- Signature

WE have to send bearer token in `Header` in every resquest if we want to authorize the resquest.

### How do JSON Web Tokens work

In authentication, when the user successfully logs in using their credentials, a JSON Web Token will be returned. Since tokens are credentials, great care must be taken to prevent security issues. In general, you should not keep tokens longer than required.

```
Authorization: Bearer <token>
```
Real Structure : 
```
var token = localStorage.getItem('token');
headers: { 
            "Content-Type": "application/json",
            "Authorization" : `Bearer ${token}`, 
        }
```
## Installation process

Install via composer \
Run the following command to pull in the latest version:
```
composer require tymon/jwt-auth
```

Add service provider \
Add the service provider to the `providers` array in the `config/app.php` config file as follows:

```
'providers' => [

    .....

    Tymon\JWTAuth\Providers\LaravelServiceProvider::class,
]
```

Publish the config \
Run the following command to publish the package config file:

```
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```

Generate secret key \
I have included a helper command to generate a key for you:

```
php artisan jwt:secret
```

This will update our `.env` file with something like `JWT_SECRET=foobar`\

It is the key that will be used to sign our tokens. How that happens exactly will depend on the algorithm that we choose to use. \

----------------------------------------------------- ### --------------------------------------------- 

## After Installation process
### Update our User model
Firstly you need to implement the `Tymon\JWTAuth\Contracts\JWTSubject` contract on your User model, which requires that you implement the 2 methods `getJWTIdentifier()` and `getJWTCustomClaims()`.

The Model Should look like this :

```php
<?php

namespace App;

use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable implements JWTSubject
{
    use Notifiable;

    // Rest omitted for brevity

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}
```

### Configure Auth guard 
Note: This will only work if you are using Laravel 5.2 and above.

Inside the `config/auth.php` file you will need to make a few changes to configure Laravel to use the `jwt` guard to power your application authentication.

Make the following changes to the file:

```
'defaults' => [
    'guard' => 'api',
    'passwords' => 'users',
],

...

'guards' => [
    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
],
```
Here we are telling the `api` guard to use the `jwt` driver, and we are setting the `api` guard as the default.

### Add some basic authentication routes
First let's add some routes in `routes/api.php` as follows:

```
use App\Http\Controllers\AuthController;
------------------------------------------------------------------------------------
Route::group(['middleware' => ['api']], ['prefix' => ['auth']], function () {

    Route::post('/login', [AuthController::class, 'login'])->name('');
    Route::post('/logout', [AuthController::class, 'logout'])->name('');
    Route::post('/refresh', [AuthController::class, 'refresh'])->name('');
    Route::post('/me', [AuthController::class, 'me'])->name('');

});
```

### Create the AuthController 
Then create the `AuthController`, either manually or by running the artisan command:
```
php artisan make:controller AuthController
```

Then add the following :

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }

    /**
     * Get a JWT token via given credentials.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if ($token = $this->guard()->attempt($credentials)) {
            return $this->respondWithToken($token);
        }

        return response()->json(['error' => 'Unauthorized'], 401);
    }

    /**
     * Get the authenticated User
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json($this->guard()->user());
    }

    /**
     * Log the user out (Invalidate the token)
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        $this->guard()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken($this->guard()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $this->guard()->factory()->getTTL() * 60
        ]);
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\Guard
     */
    public function guard()
    {
        return Auth::guard();
    }
}
```
