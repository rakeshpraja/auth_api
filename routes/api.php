<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use Tymon\JWTAuth\JWTAuth;

Route::post('register',[AuthController::class,'register']);
Route::get('verify/{token}',[AuthController::class,'verify'])->name('verify.user');

Route::post('login',[AuthController::class,'login']);

Route::post('password_forgot', [AuthController::class, 'forgotPassword']);
Route::post('password_reset/', [AuthController::class, 'resetPassword']);


Route::group(['middleware' => 'auth:api'], function () {
    Route::post('update_profile',[AuthController::class,'updateProfile']);
    
    Route::post('update_profile_verify',[AuthController::class,'verifyUpdateProfile'])->name('update.profileverify');
    Route::post('logout',[AuthController::class,'logout']);
});



