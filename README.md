#AgCalculator 
Udapte
using Microsoft.AspNetCore.Mvc;
using Syntizen.Gateway.DAL.sws;
using Syntizen.SWS.API.Models;
using Syntizen.SWS.API.Models.SDK;

namespace Syntizen.SWS.API.Controllers
{
    public partial class SWSController : ControllerBase
    {
        [ActionName("AgeCalculator")]
        [HttpPost]
        public ActionResult<string> AgeCalculator()
        {
            string apikey = "";
            DateTime dtReq = DateTime.Now;
            UserTokenDetails utd = new UserTokenDetails();
            var request = new StreamReader(Request.Body).ReadToEnd();
            if (HttpContext.Request.Headers.ContainsKey("apikey"))
            {
                apikey = "" + HttpContext.Request.Headers["apikey"];
                if (HttpContext.Request.Headers.ContainsKey("authkey"))
                {
                    if (!TokenManager.ValidateToken("" + HttpContext.Request.Headers["authkey"], ref utd, _swsContext))
                    {
                        _logger.LogDebug("Method Exit.. Response: " + utd.status);
                        return Content(JsonResponseBuilder.error("403", "" + utd.status, (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                    }
                }
                else
                {
                    _logger.LogDebug("Method Exit.. Response: Missing Auth Key");
                    return Content(JsonResponseBuilder.error("S-402", "Missing Auth Key", (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                }

              if(!Utilities.isVAPT(apikey,""+utd.username))
              {
                    _logger.LogDebug("Method Exit.. Response: Missing Auth Key");
                    return Content(JsonResponseBuilder.error("S-401", "Invalid Request.", (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");

              }
            }
            else
            {
                _logger.LogDebug("Method Exit.. Response: Invalid Request");
                return Content(JsonResponseBuilder.error("S-400", "Invalid Request", "", (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
            }
            try
            {
                _logger.LogInformation("Request Method Start..");
                string req = request;
                Utilities.IsLogEnable(utd.uid, "Encrypted Request Data : " + req, _logger, _swsContext);

                try
                {
                    //Decrypt the Request With ApiKey.
                    req = ClientSecurity.DecryptStringAES(req, apikey, _swsContext);
                    Utilities.IsLogEnable(utd.uid, "Decrypted Request Data : " + req, _logger, _swsContext);
                }
                catch (Exception)
                {                    
                    _logger.LogDebug("Method Exit.. Response: Unable to Decrypt the Request");
                    return Content(JsonResponseBuilder.error("S-401", "Invalid API Key", "", (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                }
                string IPaddress = Utilities.GetIPAddress(_httpContextAccessor, _logger);
                if (Utilities.IsIPEnable(utd.uid, IPaddress, _logger, _swsContext))
                {
                    if (req != "")
                    {
                        //Validate Json Format
                        if (Syntizen.SWS.API.Models.Utilities.IsValidJson(req))
                        {
                            //Validate Json Schema
                            if (Syntizen.SWS.API.Models.Utilities.ValidateModel<AgeDetection>(req))
                            {
                                //Loading Request to Class Object
                                AgeDetection gp = new AgeDetection();
                                gp = Newtonsoft.Json.JsonConvert.DeserializeObject<AgeDetection>(req)!;
                                if (!string.IsNullOrEmpty(utd.slk))
                                {
                                    if (!string.IsNullOrEmpty(gp.adimage))
                                    {
                                        //Validate Service id.
                                        var ser = _swsContext.Services.FirstOrDefault(s => s.Sid == (int)Commons.ServiceIDs.AgeCalculator);
                                        if (ser != null)
                                        {
                                            //Vaidating Account,License key, Service
                                            UserAccount userAccount = Syntizen.SWS.API.Models.Utilities.VerifyUserAccountService(utd.uid, utd.slk, "" + ser.Sid, "", _storedProcedureCall, _logger, _swsContext);
                                            if (userAccount.UAStatus)
                                            {
                                                if (Syntizen.SWS.API.Models.Utilities.IsBase64_GetLength("" + gp.adimage) > 0)
                                                {
                                                    string filetype = Syntizen.SWS.API.Models.Utilities.GetFileExtension("" + gp.adimage);
                                                    if (filetype == "jpg" || filetype == "png" || filetype == "jpeg")
                                                    {
                                                        if (Syntizen.SWS.API.Models.Utilities.ValidateFileSize(filetype, "" + gp.adimage, _logger, _swsContext))
                                                        {
                                                            SDKResponse sr = new SDKResponse();
                                                            DateTime oemdtReq = DateTime.Now;

                                                            //AgeCalculator data using SDK
                                                            sr = AgeDetectionSDK.AgeCalculator(gp.adimage, utd.uid, gp.rrn, _swsContext, _logger);

                                                            DateTime oemdtRes = DateTime.Now;

                                                            #region TransactionLog_WalletDeduction

                                                            //Insert Transaction Data
                                                            Transaction tr = new Transaction();
                                                            tr.Tdid = 0;
                                                            tr.Uid = Convert.ToInt32(utd.uid);
                                                            tr.Appid = userAccount.Userid;
                                                            tr.Sid = (int)Commons.ServiceIDs.AgeCalculator;
                                                            tr.Odid = Syntizen.SWS.API.Models.Utilities.GetOemID(utd.uid, (int)Commons.ServiceIDs.AgeCalculator, _swsContext, _logger);
                                                            tr.Rrn = gp.rrn;
                                                            tr.Ref1 = "";
                                                            tr.Ref2 = "";
                                                            tr.Ref3 = "";
                                                            tr.Errcode = "" + sr.respcode;
                                                            tr.Errmsg = "" + sr.respdesc;
                                                            tr.Oemtxnid = "" + sr.oemtxnid;
                                                            if (sr.respcode == "SDK500" || sr.respcode == "500")
                                                            {
                                                                tr.Oemstatus = 0;
                                                                tr.Oemref1 = "";
                                                                tr.Oemref2 = "";
                                                                tr.Oemref3 = "";
                                                                tr.Txnstatus = 3;
                                                                tr.Tcost = Convert.ToDecimal(0);
                                                                tr.Status = 0;
                                                            }
                                                            else
                                                            {
                                                                tr.Txnstatus = 1;
                                                                tr.Oemref1 = "";
                                                                tr.Oemref2 = "";
                                                                tr.Oemref3 = "";
                                                                tr.Oemstatus = sr.oemstatus;
                                                                if (Syntizen.SWS.API.Models.Utilities.LockTransAmountDeductions(utd.uid, userAccount.Acctype, userAccount.Accid, userAccount.TCost, Convert.ToInt32(tr.Sid), Convert.ToInt32(tr.Odid), _swsContext, _logger))
                                                                {
                                                                    tr.Tcost = userAccount.TCost;
                                                                    tr.Status = 1;
                                                                    tr.Isbillable = 1;
                                                                }
                                                                else
                                                                {
                                                                    tr.Tcost = Convert.ToDecimal(0);
                                                                    tr.Status = 0;
                                                                    tr.Isbillable = 0;
                                                                }
                                                            }
                                                            DateTime dtRes = DateTime.Now;
                                                            tr.Userreqdt = dtReq;
                                                            tr.Userresdt = dtRes;
                                                            tr.Txnttl = (int)dtRes.Subtract(dtReq).TotalMilliseconds;
                                                            tr.Oemreqdt = oemdtReq;
                                                            tr.Oemresdt = oemdtRes;
                                                            tr.Oemttl = (int)oemdtRes.Subtract(oemdtReq).TotalMilliseconds;
                                                            tr.Deviceid = "";
                                                            tr.Devicemac = "";
                                                            tr.Location = "";
                                                            tr.Ipaddress = "" + Syntizen.SWS.API.Models.Utilities.GetIPAddress(_httpContextAccessor, _logger);
                                                            tr.Txndate = dtReq;
                                                            tr.Apiver = "" + Syntizen.SWS.API.Models.Utilities.GetAssemblyFileVersion();
                                                            _swsContext.Transactions.Add(tr);
                                                            _swsContext.SaveChanges();

                                                            #endregion

                                                            sr.txnid = "" + gp.rrn;
                                                            if (sr.oemstatus == 1)
                                                                return Content(JsonResponseBuilder.success("200", "Success.", sr, (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                                                            else
                                                                return Content(JsonResponseBuilder.error(sr.respcode, sr.respdesc, gp.rrn, (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                                                        }
                                                        else
                                                        {
                                                            _logger.LogDebug("Method Exit.. Response: Size of the File exceeded the limit (8MB)");
                                                            return Content(JsonResponseBuilder.error("S-520", "Size of the File exceeded the limit (8MB)", "" + gp.rrn, (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                                                        }
                                                    }
                                                    else
                                                    {
                                                        _logger.LogDebug("Method Exit.. Response: Unsupported format, Supports only jpg, png, pdf");
                                                        return Content(JsonResponseBuilder.error("S-430", "Unsupported format, Supports only jpg, png, pdf", "" + gp.rrn, (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                                                    }
                                                }
                                                else
                                                {
                                                    _logger.LogDebug("Method Exit.. Response: Invalid Base64");
                                                    return Content(JsonResponseBuilder.error("429", "Invalid Base64", "" + gp.rrn, (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                                                }
                                            }
                                            else
                                            {
                                                _logger.LogDebug("Method Exit.. Response: " + userAccount.UAErrDesc);
                                                return Content(JsonResponseBuilder.error(userAccount.UAErrCode, userAccount.UAErrDesc, "" + gp.rrn, (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                                            }
                                        }
                                        else
                                        {
                                            _logger.LogDebug("Method Exit.. Response: Invalid ServiceID");
                                            return Content(JsonResponseBuilder.error("S-428", "Invalid ServiceID", "" + gp.rrn, (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                                        }
                                    }
                                    else
                                    {
                                        _logger.LogDebug("Method Exit.. Response: DebitCard Image Missing");
                                        return Content(JsonResponseBuilder.error("S-427", "DebitCard Image Missing", "" + gp.rrn, (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                                    }
                                }
                                else
                                {
                                    _logger.LogDebug("Method Exit.. Response: Empty SLK");
                                    return Content(JsonResponseBuilder.error("S-407", "Empty SLK", "" + gp.rrn, (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                                }
                            }
                            else
                            {
                                _logger.LogDebug("Method Exit.. Response: Schema Validation Failed");
                                return Content(JsonResponseBuilder.error("403", "Schema Validation Failed", "", (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                            }
                        }
                        else
                        {
                            _logger.LogDebug("Method Exit.. Response: Unable to parse Json");
                            return Content(JsonResponseBuilder.error("S-405", "Unable to parse Json", "", (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                        }
                    }
                    else
                    {
                        _logger.LogDebug("Method Exit.. Response: Empty Request");
                        return Content(JsonResponseBuilder.error("S-404", "Empty Request", "", (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
                    }
                }
                else
                {
                    _logger.LogDebug("Method Exit.. Response: IP not Whitelisted");
                    return Content(JsonResponseBuilder.error("S-523", "This IP " + IPaddress + " is not whitelisted. Please contact support team!", "", (int)Commons.APICodes.ManageAccounts, apikey, _swsContext), "application/json");
                }
            }
            catch (Exception ex)
            {
                
                _logger.LogError("Method Exit.. " + ex.Message, ex);
                return Content(JsonResponseBuilder.error("S-500", "Something went wrong. Please try again later.", "", (int)Commons.APICodes.AgeCalculator, apikey, _swsContext), "application/json");
            }
        }
    }
}
