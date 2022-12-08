// import { Controller, Get, Req, Request, Res, Response, UseGuards } from '@nestjs/common';
import { Controller, Get, Post, Req, Body, Res, UnauthorizedException, UseGuards } from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';
import { request } from 'http';
import { authenticator } from 'otplib';
import { VeriftyTfaDto} from './dtos/tfa.dto';

@Controller('auth')
export class AuthController {
	constructor(private readonly authService: AuthService) {}

	@Get('/signup')
	@UseGuards(AuthGuard('42'))
	async authentication() {
		// console.log("trying to auth")
	}

	@Get('/redirect')
	@UseGuards(AuthGuard('42'))
	async login(@Req() request, @Res({passthrough:true}) res: Response) {

		const user =  await this.authService.findORcreate(request.user);

		if (user.tfa === true) {
			// redirect to 2fa page
			return res.status(200).send(user.id);
		}

		const token = await this.authService.JwtAccessToken(user.id);

		const secretData = {
			token,
		}

		//If you are setting the cookie on a response in a login route in express backend for JWT and are using 'httpOnly' option is true.
		res.cookie(
			process.env.AUTHCOOKIE,
			secretData.token,
			{httpOnly:true,}
		);

		return res.status(302).redirect(`http://localhost:3000/`);
	}

	@Post('/2fa/verify')
	async verify2fa(@Body() body: VeriftyTfaDto, @Req() request, @Res() res: Response) {
		const user = await this.authService.findById(body.player_id);
		if (!user) {
			throw new UnauthorizedException('User not found');
		}
		// const is_code_valid = this.authService.is2faCodeValid(user, request.body.code);

		if (!user.tfaSecret) {
			throw new UnauthorizedException('2fa not enabled');
		}
		const is_code_valid = await authenticator.verify({ token: body.code, secret: user.tfaSecret});
		if (!is_code_valid) {
			throw new UnauthorizedException('Invalid code');
		}
		// return res.send({
		// 	message: '2fa verified'
		// });


		const token = await this.authService.JwtAccessToken(user.id);

		const secretData = {
			token,
		}

		//If you are setting the cookie on a response in a login route in express backend for JWT and are using 'httpOnly' option is true.
		res.cookie(
			process.env.AUTHCOOKIE,
			secretData.token,
			{httpOnly:true,}
		);

		return res.status(302).redirect(`http://localhost:3000/`);
	}

	@Get('/logout')
	@UseGuards(AuthGuard('jwt'))
	async logout(@Req() request, @Res({passthrough:true}) res: Response) {
		res.clearCookie(process.env.AUTHCOOKIE);
		return res.status(302).redirect(`http://localhost:3000/`);
	}
}