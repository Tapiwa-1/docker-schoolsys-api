<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\ForgetPasswordRequest;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\LogoutRequest;
use App\Http\Requests\Auth\RegisterRequest;
use App\Http\Requests\Auth\ResetPasswordRequest;
use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
    {
        try {

            $user = User::create([
                'first_name' => $request->input('first_name'),
                'last_name' => $request->input('last_name'),
                'email' => $request->input('email'),
                'password' => Hash::make($request->input('password'))
            ]);

            $token = $user->createToken('user_token')->plainTextToken;

            return response()->json([ 'user' => $user, 'token' => $token ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'error' => $e->getMessage(),
                'message' => 'Something went wrong in AuthController.register'
            ]);
        }
    }

    public function forgetPassword(ForgetPasswordRequest $request){
         try {

                $status = Password::sendResetLink(
                    $request->only('email')
                );

                $status === Password::RESET_LINK_SENT
                            ? back()->with(['status' => __($status)])
                            : back()->withErrors(['email' => __($status)]);

                return response()->json($status, 200);

        } catch (\Exception $e) {
            return response()->json([
                'error' => $e->getMessage(),
                'message' => 'Something went wrong in AuthController.forgetPassword'
            ]);
        }
    }

    public function resetPassword(ResetPasswordRequest $request){

        try{
            $status = Password::reset(
                $request->only('email', 'password', 'password_confirmation', 'token'),
                function ($user, $password) {
                    $user->forceFill([
                        'password' => Hash::make($password)
                    ])->setRememberToken(Str::random(60));
                    $user->save();
                    event(new PasswordReset($user));
                });
            return response()->json($status, 200);
        }catch (\Exception $e) {
            return response()->json([
                'error' => $e->getMessage(),
                'message' => 'Something went wrong in AuthController.ResetPassword'
            ]);
        }
    }
    public function login(LoginRequest $request)
    {
        try {

            $user = User::where('email', '=', $request->input('email'))->firstOrFail();


            if (Hash::check($request->input('password'), $user->password)) {
                $token = $user->createToken('user_token')->plainTextToken;

                return response()->json([ 'user' => $user, 'token' => $token ], 200);
            }

            return response()->json([ 'error' => 'Something went wrong in login' ]);

        } catch (\Exception $e) {
            return response()->json([
                'error' => $e->getMessage(),
                'message' => 'Something went wrong in AuthController.login'
            ]);
        }
    }

    public function logout(LogoutRequest $request)
    {
        try {

            $user = User::findOrFail($request->input('user_id'));

            $user->tokens()->delete();

            return response()->json('User logged out!', 200);

        } catch (\Exception $e) {
            return response()->json([
                'error' => $e->getMessage(),
                'message' => 'Something went wrong in AuthController.logout'
            ]);
        }
    }
}
