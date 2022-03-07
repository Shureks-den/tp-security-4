import { Database } from './db.js';
import express, { json } from 'express';
import axios from 'axios';
export const app = express();

app.use(express.json());

app.get('/requests', async (req, res) => {
    try {
        const answer = await Database.getAllInfo();
        res.json(answer);
    } catch (e) {
        res.json(e);
    }
})

app.get('/request/:id', async (req, res) => {
    try {
        const answer = await Database.getInfoById(req.params.id);
        res.json(answer);
    } catch (e) {
        res.json(e);
    }
})

app.get('/repeat/:id', async (req, res) => {
    try {
        const answer = await Database.getInfoById(req.params.id);
        const path = answer.request.isSecure ? answer.request.path :
            '/' + answer.request.path.split('/').slice(1).join('/');
        let url = answer.request.isSecure ? 'https://' + `${answer.request.host}${path}` :
            'http://' + `${answer.request.host}${path}`;
        const getParams = answer.request.get_params == '' ? {} : JSON.parse(answer.request.get_params);
        if (Object.keys(getParams).length > 0) {
            url += '?';
            for (let key in getParams) {
                url += `${key}=${getParams[key]}&`;
            }
        }
        axios({
            url: url,
            method: answer.request.method,
            headers: JSON.parse(answer.request.headers),
            data: (answer.request.method !== 'GET' && answer.request.method !== 'HEAD') ? 
                answer.request.post_params : undefined,
            withCredentials: true,
            maxRedirects: 0,
            validateStatus: function (status) {
                return status >= 200 && status < 500;
              }
        }).then((resp) => {
            res.json({status: resp.status, statusText: resp.statusText, data: resp.data});
        });
    } catch (e) {
        res.json(e);
    }
})

app.get('/inject/:id', async (req, res) => {
    try {
        const answer = await Database.getInfoById(req.params.id);
        const path = answer.request.isSecure ? answer.request.path :
            '/' + answer.request.path.split('/').slice(1).join('/');
        let url = answer.request.isSecure ? 'https://' + `${answer.request.host}${path}` :
            'http://' + `${answer.request.host}${path}`;
        let tryCount = 0;
        const getParams = answer.request.get_params == '' ? {} : JSON.parse(answer.request.get_params);

        const postParams = {}, re = new RegExp('(.*?)=(.*?)(?:&|$)','g');
        answer.request.post_params.replace(re, (_, key, value) => postParams[key.trim()] = value.trim());

        const cookies = {}, reForCookies = new RegExp('(.*?)=(.*?)(?:,|$)','g');
        answer.request.cookies.replace(reForCookies, (_, key, value) => cookies[key.trim()] = value.trim());

        const headers = JSON.parse(answer.request.headers);
        const allCount = (Object.keys(getParams).length + Object.keys(postParams).length +
            Object.keys(cookies).length) * 2;
        
        console.log('Potential attacks count: ', Object.keys(getParams).length + 
            Object.keys(postParams).length + Object.keys(cookies).length)
        console.log(answer.request.cookies)
        while (tryCount < allCount) {
            console.log('try number:', tryCount)
            if (Object.keys(getParams).length > 0) {
                url += '?';
                let i = 0;
                for (let key in getParams) {
                    if (i == tryCount) {
                        url += `${key}=${getParams[key]}'&`;  
                    } else if (i == tryCount - getParams.length) {
                        url += `${key}=${getParams[key]}"&`;
                    } else {
                        url += `${key}=${getParams[key]}"&`;
                    }
                }
                i++;
            }

            if (Object.keys(postParams).length > 0) {
                let i = 0;
                for (let key in postParams) {
                    if (i == tryCount - 2 * Object.keys(getParams).length) {
                        postParams[key] = postParams[key] + `'`;
                    } else if (i == tryCount - 2 * Object.keys(getParams).length - Object.keys(postParams).length) {
                        postParams[key] = postParams[key] + `"`;
                    }
                    i++;
                }   
            }
            const newPostString = JSON.stringify(postParams).replaceAll('{', '').replaceAll('}', '').
                replaceAll('"', '').replaceAll(':', '=').replaceAll(',', '&');

            if (Object.keys(cookies).length > 0) {
                let i = 0;
                for (let key in cookies) {
                    if (i == tryCount - 2 * getParams.length - 2 * postParams.length) {
                        cookies[key] = cookies[key] + `'`;
                    } else if (i == tryCount - 2 * getParams.length - 2 * postParams.length - cookies.length) {
                        cookies[key] = cookies[key] + `"`;
                    }
                }
                i++;
                headers.cookies = cookies;
            }

            const resp = await axios({
                url: url,
                method: answer.request.method,
                headers: headers,
                data: (answer.request.method !== 'GET' && answer.request.method !== 'HEAD') ? 
                    answer.request.post_params : undefined,
                withCredentials: true,
                maxRedirects: 0,
                validateStatus: function (status) {
                    return status >= 200 && status < 500;
                  }
            })
            if (resp.status != answer.response.code || resp.data.length != answer.response.body.length) {
                let vector;
                if (tryCount < 2 * Object.keys(getParams).length) {
                    vector = 'Get Params';
                } else if (tryCount >= 2 * Object.keys(getParams).length && 
                    tryCount < 2 * Object.keys(getParams).length + 2 * Object.keys(postParams).length) {
                    vector = 'Post Params';
                } else {
                    vector = 'Cookies';
                }
                res.json({status: 200, statusText: "Found injection", data: {
                    url: url,
                    method: answer.request.method,
                    headers: headers,
                    data: (answer.request.method !== 'GET' && answer.request.method !== 'HEAD') ? 
                        newPostString : undefined,
                    message: 'This url is vulnurable to sql injection',
                    attackVector: vector
                }});
                return;
            }
            tryCount++;
        }
        res.json({status: 404, statusText: "Not Found", data:  {message: "No injection found"}});
    } catch (e) {
        res.json(e);
    }
})
