import {
    HttpEvent,
    HttpHandler,
    HttpInterceptor,
    HttpRequest,
} from '@angular/common/http'
import { Injectable } from '@angular/core'
import { Auth } from '@aws-amplify/auth'
import { from, Observable } from 'rxjs'
import { switchMap } from 'rxjs/operators'

import { environment } from './../../../environments/environment'

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
    intercept(
        request: HttpRequest<unknown>,
        next: HttpHandler
    ): Observable<HttpEvent<unknown>> {
        if (request.url.includes(environment.TSP_BASE_URL_ADMIN)) {
            return from(Auth.currentAuthenticatedUser()).pipe(
                switchMap((res) => {
                    const authReq = request.clone({
                        setHeaders: {
                            Authorization: `Bearer ${res?.signInUserSession.idToken.jwtToken}`,
                            'x-api-key': environment.production
                                ? 'facsaauhfashdjsakhdjashd77f42f6c'
                                : '0a711fhsadhsajdhasjgdasa51b4e72e',
                        },
                    })
                    return next.handle(authReq)
                })
            )
        } else if (request.url.includes(environment.APIM_URL)) {
            return from(Auth.currentAuthenticatedUser()).pipe(
                switchMap((res) => {
                    const authReq = request.clone({
                        setHeaders: {
                            Authorization: `Bearer ${res?.signInUserSession.accessToken.jwtToken}`,
                        },
                    })
                    return next.handle(authReq)
                })
            )
        } else {
            return next.handle(request)
        }
    }
}
