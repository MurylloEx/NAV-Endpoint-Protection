Namespace OpBotAPI

    Public Class OpClntSrv

        Private Class resources_t
            Public Property resourceName As String
            Public Property resourceArrayName As String
            Public Property resourceImage As String
            Public Property tooltipTitleId As String
            Public Property tooltipTextId As String
            Public Property liHasId As String
            Public Property link As String
            Public Property exchange As String
            Public Property exchangeOrder As String
            Public Property linkTarget As String
            Public Property cssClass As String
            Public Property amount As String
        End Class

        Private Class resourceBar
            Public Property resources As resources_t()
            Public Property eggs As String
        End Class

        Private Class weather_t
            Public Property id As String
            Public Property min As String
            Public Property max As String
            Public Property pic As String
            Public Property sprite_id As String
            Public Property wetterexp As String
            Public Property name As String
            Public Property extension As String
            Public Property expire As String
        End Class

        Private Class user_t
            Public Property name As String
            Public Property land As String
            Public Property rank As String
            Public Property alliance As String
        End Class

        Private Class build_t
            Public Property state As String
            Public Property amount As String
            Public Property htmlid As String
            Public Property mainId As String
            Public Property menuArrow As String
            Public Property menuArrowLeftRight As String
            Public Property title As String
        End Class

        Private Class buildings_t
            Public Property headquarter_background
            Public Property houses_background
            Public Property houses_2_background
            Public Property houses_3_background
            Public Property houses_4_background
            Public Property skyscrapers_background
            Public Property skyscrapers_2_background
            Public Property skyscrapers_3_background
            Public Property skyscrapers_4_background
            Public Property barracks_background
            Public Property ammunition_factory_background
            Public Property market_background
            Public Property refinery_background
            Public Property factory_background
            Public Property university_background
            Public Property pentagon_background
            Public Property simulator_background
            Public Property harbour_background
            Public Property airport_background
            Public Property weapon_factory_background
            Public Property palm_trees_roundabout1 As build_t
            Public Property palm_trees_roundabout2 As build_t
            Public Property palm_trees_barracks1 As build_t
            Public Property palm_trees_barracks2 As build_t
            Public Property HelicopterAnimation As build_t
            <JsonProperty(PropertyName:="1")>
            Public Property _1 As build_t
            <JsonProperty(PropertyName:="2")>
            Public Property _2 As build_t
            <JsonProperty(PropertyName:="3")>
            Public Property _3 As build_t
            <JsonProperty(PropertyName:="4")>
            Public Property _4 As build_t
            <JsonProperty(PropertyName:="8")>
            Public Property _8 As build_t
            <JsonProperty(PropertyName:="10")>
            Public Property _10 As build_t
            <JsonProperty(PropertyName:="18")>
            Public Property _18 As build_t
            <JsonProperty(PropertyName:="19")>
            Public Property _19 As build_t
            <JsonProperty(PropertyName:="20")>
            Public Property _20 As build_t
            <JsonProperty(PropertyName:="21")>
            Public Property _21 As build_t
            <JsonProperty(PropertyName:="25")>
            Public Property _25 As build_t
            <JsonProperty(PropertyName:="26")>
            Public Property _26 As build_t
            <JsonProperty(PropertyName:="30")>
            Public Property _30 As build_t
            <JsonProperty(PropertyName:="31")>
            Public Property _31 As build_t
            <JsonProperty(PropertyName:="32")>
            Public Property _32 As build_t
            <JsonProperty(PropertyName:="33")>
            Public Property _33 As build_t
            <JsonProperty(PropertyName:="34")>
            Public Property _34 As build_t
            <JsonProperty(PropertyName:="38")>
            Public Property _38 As build_t
            <JsonProperty(PropertyName:="39")>
            Public Property _39 As build_t
            <JsonProperty(PropertyName:="40")>
            Public Property _40 As build_t
            <JsonProperty(PropertyName:="42")>
            Public Property _42 As build_t
            <JsonProperty(PropertyName:="43")>
            Public Property _43 As build_t
            <JsonProperty(PropertyName:="2_2")>
            Public Property _2_2 As build_t
            <JsonProperty(PropertyName:="2_3")>
            Public Property _2_3 As build_t
            <JsonProperty(PropertyName:="2_4")>
            Public Property _2_4 As build_t
            <JsonProperty(PropertyName:="3_2")>
            Public Property _3_2 As build_t
            <JsonProperty(PropertyName:="3_3")>
            Public Property _3_3 As build_t
            <JsonProperty(PropertyName:="3_4")>
            Public Property _3_4 As build_t
            <JsonProperty(PropertyName:="38_1")>
            Public Property _38_1 As build_t
        End Class

        Private Class task_t
            Public Property id As String '
            Public Property [date] As String
            Public Property endDate As String
            Public Property referenceId As String '
            Public Property count As String
            Public Property duration As String '
            Public Property action As String '
            Public Property showCancel As String '
            Public Property isAttacker As String '
            Public Property opponentName As String '
            Public Property opponent As String '
            Public Property text As String '
            Public Property weaponName As String '
            Public Property weaponAmount As String '
            Public Property order As String '
            Public Property name As String '
            Public Property type As String '
            Public Property sType As String
            Public Property arrival As String
            Public Property start As String
        End Class

        Private Class bubble_t
            Public Property obj As Object
        End Class

        Private Class internalOpData
            Public Property GameVersion As String
            Public Property weather As weather_t
            Public Property paymentHash As String
            Public Property user As user_t
            Public Property eggs As String
            Public Property buildings As buildings_t
            Public Property tasks As task_t()
            Public Property allianceattacks As String
            Public Property bubbles As bubble_t()
        End Class


        Public Delegate Function OpRetrieveUsers(ByVal playerName As String, ByVal playerAttackable As Boolean, ByVal playerOnline As Boolean, ByVal playerHoliday As Boolean,
                                                 ByVal playerLocked As Boolean, ByVal playerProfileAddr As String, ByVal playerAllyName As String, ByVal playerAllyAddr As String,
                                                 ByVal playerPoints As String, ByVal pointsRanking As UShort, ByVal battleRanking As Short) As Boolean

        Public Delegate Sub OpRetrieveUserDetails(ByVal playerName As String, ByVal playerMail As String, ByVal playerCountry As String, ByVal playerGameCountry As String,
                                                  ByVal playerCoords As String, ByVal playerWinBattles As String, ByVal playerLostBattles As String, ByVal playerAllyFullname As String,
                                                  ByVal playerFactories As String, ByVal playerMines As String, ByVal playerRefineries As String, ByVal playerLoot As UShort,
                                                  ByVal playerPoints As String, ByVal playerBattlePoints As String, ByVal playerOnline As Boolean, ByVal playerLocked As Boolean,
                                                  ByVal playerHoliday As Boolean, ByVal playerBlocked As Boolean, ByVal playerPointsRanking As UShort, ByVal playerBattleRanking As Short)

        Public Delegate Sub OpSrvUpdateProgress(ByVal progressValue As Double, ByVal lastUserUpdated As String)

        Public Structure OpClntUserResources
            Dim Oil As String
            Dim Cerosin As String
            Dim Diesel As String
            Dim Ammunition As String
            Dim Money As String
            Dim Gold As String
            Dim Diamonds As String
            Dim Points As String
        End Structure

        Public Structure OpClntUser
            Dim Username As String
            Dim Land As String
            Dim Rank As String
            Dim Alliance As String
        End Structure

        Public Structure OpClntWeather
            Dim Id As String
            Dim Min As UShort
            Dim Max As UShort
            Dim Name As String
            Dim EndDate As DateTime
        End Structure

        Public Structure OpClntBuilding
            Dim State As String
            Dim Amount As String
            Dim Id As String
            Dim Title As String
        End Structure

        Public Structure OpClntTask
            Dim Id As String '
            Dim [Date] As DateTime
            Dim EndDate As DateTime
            Dim ReferenceId As String '
            Dim Name As String '
            Dim Duration As ULong '
            Dim Action As String '
            Dim Cancelable As Boolean '
            Dim Attacking As Boolean
            Dim OpponentName As String
            Dim OpponentHash As String
            Dim Text As String
            Dim WeaponName As String
            Dim WeaponAmount As String
            Dim Order As String
            Dim Type As String
            Dim Arrival As String
            Dim Start As String
        End Structure

        Public Structure OpClntInternalData
            Dim Version As String
            Dim PaymentHash As String
            Dim Weather As OpClntWeather
            Dim User As OpClntUser
            Dim Buildings As OpClntBuilding()
            Dim Tasks As OpClntTask()
            Dim Attacks As UShort
        End Structure

        <Serializable()>
        Public Structure OpSrvUserDefeat
            Dim InstantOfDefeats As Date
            Dim Count As UShort
        End Structure

        <Serializable()>
        Public Structure OpSrvUserVictory
            Dim InstantOfVictories As Date
            Dim Count As UShort
        End Structure

        <Serializable()>
        Public Structure OpSrvUserInfo
            Dim PlayerName As String
            Dim PlayerMail As String
            Dim PlayerCountry As String
            Dim PlayerGameCountry As String
            Dim PlayerCoords As String
            Dim PlayerWinBattles As String
            Dim PlayerLostBattles As String
            Dim PlayerAllyFullname As String
            Dim PlayerFactories As String
            Dim PlayerMines As String
            Dim PlayerRefineries As String
            Dim PlayerLoot As UShort
            Dim PlayerPoints As String
            Dim PlayerBattlePoints As String
            Dim PlayerOnline As Boolean
            Dim PlayerLocked As Boolean
            Dim PlayerHoliday As Boolean
            Dim PlayerBlocked As Boolean
            Dim PlayerPointsRanking As UShort
            Dim PlayerBattleRanking As Short
            Dim LastTimeOnline As Date
            Dim LastDefeats As List(Of OpSrvUserDefeat)
            Dim LastVictories As List(Of OpSrvUserVictory)
        End Structure

        <Serializable()>
        Public Structure OpSrvInformationScheme
            Dim Players As List(Of OpSrvUserInfo)
        End Structure

        Public Structure EngOpSrvUpd

            Public EngOpSrvScheme As OpSrvInformationScheme
            Public EngOpAuthCookies As CookieContainer
            Public EngOpUpdateProgress As OpSrvUpdateProgress
            Public EngOpSrvTotalUsers As UInt32
            Shared EngOpSrvUserCount As UInt32

            Public Function OpRetrieveUsersCallback(ByVal playerName As String, ByVal playerAttackable As Boolean, ByVal playerOnline As Boolean,
                                                    ByVal playerHoliday As Boolean, ByVal playerLocked As Boolean, ByVal playerProfileAddr As String,
                                                    ByVal playerAllyName As String, ByVal playerAllyAddr As String, ByVal playerPoints As String,
                                                    ByVal pointsRanking As UShort, ByVal battleRanking As Short) As Boolean
                OpSrvRetrieveUserDetails(EngOpAuthCookies, AddressOf EngOpRetrieveUserDetails, playerProfileAddr)
                Return True
            End Function

            Public Sub EngOpRetrieveUserDetails(ByVal playerName As String, ByVal playerMail As String, ByVal playerCountry As String,
                                                ByVal playerGameCountry As String, ByVal playerCoords As String, ByVal playerWinBattles As String,
                                                ByVal playerLostBattles As String, ByVal playerAllyFullname As String, ByVal playerFactories As String,
                                                ByVal playerMines As String, ByVal playerRefineries As String, ByVal playerLoot As UShort,
                                                ByVal playerPoints As String, ByVal playerBattlePoints As String, ByVal playerOnline As Boolean,
                                                ByVal playerLocked As Boolean, ByVal playerHoliday As Boolean, ByVal playerBlocked As Boolean,
                                                ByVal playerPointsRanking As UShort, ByVal playerBattleRanking As Short)
                If (EngOpSrvUserCount >= EngOpSrvTotalUsers) Then
                    EngOpSrvUserCount = 0
                End If
                If (EngOpSrvScheme.Players.Count > 0) Then
                    For userIndex As UInt32 = 0 To (EngOpSrvScheme.Players.Count - 1)
                        If (EngOpSrvScheme.Players(userIndex).PlayerName.ToUpper = playerName.ToUpper) Then
                            EngOpSrvUserCount += 1
                            Dim CurrUser As New OpSrvUserInfo
                            CurrUser.LastDefeats = EngOpSrvScheme.Players(userIndex).LastDefeats
                            CurrUser.LastVictories = EngOpSrvScheme.Players(userIndex).LastVictories
                            CurrUser.LastTimeOnline = EngOpSrvScheme.Players(userIndex).LastTimeOnline
                            With CurrUser
                                .PlayerName = playerName
                                .PlayerMail = playerMail
                                .PlayerCountry = playerCountry
                                .PlayerGameCountry = playerGameCountry
                                .PlayerCoords = playerCoords
                                .PlayerWinBattles = playerWinBattles
                                .PlayerLostBattles = playerLostBattles
                                .PlayerAllyFullname = playerAllyFullname
                                .PlayerFactories = playerFactories
                                .PlayerMines = playerMines
                                .PlayerRefineries = playerRefineries
                                .PlayerLoot = playerLoot
                                .PlayerPoints = playerPoints
                                .PlayerBattlePoints = playerBattlePoints
                                .PlayerOnline = playerOnline
                                .PlayerLocked = playerLocked
                                .PlayerHoliday = playerHoliday
                                .PlayerBlocked = playerBlocked
                                .PlayerPointsRanking = playerPointsRanking
                                .PlayerBattleRanking = playerBattleRanking
                            End With
                            If (playerOnline = True) Then
                                CurrUser.LastTimeOnline = Date.Now
                            End If
                            If (CUShort(playerWinBattles) > CUShort(EngOpSrvScheme.Players(userIndex).PlayerWinBattles)) Then
                                If (CurrUser.LastVictories Is Nothing) Then
                                    CurrUser.LastVictories = New List(Of OpSrvUserVictory)
                                End If
                                Dim lastVic As New OpSrvUserVictory
                                lastVic.Count = (CUShort(playerWinBattles) - CUShort(EngOpSrvScheme.Players(userIndex).PlayerWinBattles))
                                lastVic.InstantOfVictories = Date.Now
                                CurrUser.LastVictories.Add(lastVic)
                            End If
                            If (CUShort(playerLostBattles) > CUShort(EngOpSrvScheme.Players(userIndex).PlayerLostBattles)) Then
                                If (CurrUser.LastDefeats Is Nothing) Then
                                    CurrUser.LastDefeats = New List(Of OpSrvUserDefeat)
                                End If
                                Dim lastDef As New OpSrvUserDefeat
                                lastDef.Count = (CUShort(playerLostBattles) - CUShort(EngOpSrvScheme.Players(userIndex).PlayerLostBattles))
                                lastDef.InstantOfDefeats = Date.Now
                                CurrUser.LastDefeats.Add(lastDef)
                            End If
                            EngOpSrvScheme.Players(userIndex) = CurrUser
                            EngOpUpdateProgress(EngOpSrvUserCount / EngOpSrvTotalUsers, playerName)
                            Exit Sub
                        End If
                    Next
                End If
                EngOpSrvUserCount += 1
                Dim OpSrvCurrentUser As New OpSrvUserInfo
                With OpSrvCurrentUser
                    .PlayerName = playerName
                    .PlayerMail = playerMail
                    .PlayerCountry = playerCountry
                    .PlayerGameCountry = playerGameCountry
                    .PlayerCoords = playerCoords
                    .PlayerWinBattles = playerWinBattles
                    .PlayerLostBattles = playerLostBattles
                    .PlayerAllyFullname = playerAllyFullname
                    .PlayerFactories = playerFactories
                    .PlayerMines = playerMines
                    .PlayerRefineries = playerRefineries
                    .PlayerLoot = playerLoot
                    .PlayerPoints = playerPoints
                    .PlayerBattlePoints = playerBattlePoints
                    .PlayerOnline = playerOnline
                    .PlayerLocked = playerLocked
                    .PlayerHoliday = playerHoliday
                    .PlayerBlocked = playerBlocked
                    .PlayerPointsRanking = playerPointsRanking
                    .PlayerBattleRanking = playerBattleRanking
                End With
                If (playerOnline = True) Then
                    OpSrvCurrentUser.LastTimeOnline = Date.Now
                End If
                EngOpSrvScheme.Players.Add(OpSrvCurrentUser)
                EngOpUpdateProgress(EngOpSrvUserCount / EngOpSrvTotalUsers, playerName)
            End Sub

        End Structure



        Public Function OpSrvRetrieveUsers(ByRef s_cookies As CookieContainer, ByVal OpRetrieveUsersCallback As OpRetrieveUsers, ByVal startIndex As UShort, ByVal endIndex As UShort, ByVal OpWorld As String, ByVal OpRemoteAddr As String) As Boolean
            Try
                Dim d_response As String
                Using d_get As New Ajax(Replace(OpRemoteAddr & "/{WORLD}/highscore.php", "{WORLD}", OpWorld), System.Text.Encoding.UTF8, s_cookies, AjaxType.AjaxGET)
                    d_response = d_get.Send("mode=1&von=" & startIndex & "&end=" & (endIndex + 1))
                End Using
                Dim htmlDoc As New HtmlDocument()
                htmlDoc.LoadHtml(d_response)
                Dim nodes As HtmlNodeCollection = htmlDoc.DocumentNode.SelectNodes("//table/tbody/tr")
                For nodeIndex As Integer = 0 To nodes.Count - 1
                    Dim node1 As HtmlNode = htmlDoc.DocumentNode.SelectNodes("//table/tbody/tr/*[contains(@class,'td1')]")(nodeIndex)
                    Dim node2 As HtmlNode = htmlDoc.DocumentNode.SelectNodes("//table/tbody/tr/*[contains(@class,'td2')]")(nodeIndex)
                    Dim node3 As HtmlNode = htmlDoc.DocumentNode.SelectNodes("//table/tbody/tr/*[contains(@class,'td3')]")(nodeIndex)
                    Dim node4 As HtmlNode = htmlDoc.DocumentNode.SelectNodes("//table/tbody/tr/*[contains(@class,'td4')]")(nodeIndex)
                    Dim node5 As HtmlNode = htmlDoc.DocumentNode.SelectNodes("//table/tbody/tr/*[contains(@class,'td5')]")(nodeIndex)
                    Dim rankPoints As UShort
                    Dim rankBattle As Short
                    Dim playerName As String
                    Dim playerAttackable As Boolean
                    Dim playerHoliday As Boolean
                    Dim playerOnline As Boolean
                    Dim playerLocked As Boolean
                    Dim playerProfileAddr As String
                    Dim playerAllyName As String
                    Dim playerAllyAddr As String
                    Dim playerPoints As String
                    If (node1.SelectSingleNode("strong") IsNot Nothing) Then
                        rankPoints = CUShort(node1.SelectSingleNode("strong").InnerText)
                    Else
                        rankPoints = CUShort(node1.InnerText)
                    End If
                    If (node2.InnerText.Trim = "-") Then
                        rankBattle = -1
                    Else
                        rankBattle = CShort(node2.InnerText)
                    End If
                    Dim playerNameNode As HtmlNode = node3.SelectSingleNode("a")
                    playerName = playerNameNode.SelectSingleNode("strong").InnerText
                    If (playerNameNode.SelectSingleNode("img") IsNot Nothing) Then
                        If (playerNameNode.SelectSingleNode("img").Attributes("src").Value.Contains("weather_sun")) Then
                            playerHoliday = True
                        Else
                            playerHoliday = False
                        End If
                        If (playerNameNode.SelectSingleNode("img").Attributes("src").Value.Contains("bullet_green")) Then
                            playerOnline = True
                        Else
                            playerOnline = False
                        End If
                        If (playerNameNode.SelectSingleNode("img").Attributes("src").Value.Contains("lock_go")) Then
                            playerLocked = True
                        Else
                            playerLocked = False
                        End If
                    Else
                        playerHoliday = False
                        playerOnline = False
                        playerLocked = False
                    End If
                    If (node3.SelectSingleNode("a").SelectSingleNode("strong").HasClass("playerAttackable")) Then
                        playerAttackable = True
                    Else
                        playerAttackable = False
                    End If
                    playerProfileAddr = String.Concat({OpRemoteAddr & "/" & OpWorld & "/", node3.SelectSingleNode("a").Attributes("href").Value})
                    Dim allyNode As HtmlNode = node4.SelectSingleNode("a")
                    If (allyNode IsNot Nothing) Then
                        playerAllyName = allyNode.InnerText
                        playerAllyAddr = allyNode.Attributes("href").Value
                    Else
                        playerAllyName = String.Empty
                        playerAllyAddr = String.Empty
                    End If
                    playerPoints = node5.SelectSingleNode("span").Attributes("data").Value
                    If (OpRetrieveUsersCallback(playerName, playerAttackable, playerOnline, playerHoliday, playerLocked, playerProfileAddr, playerAllyName, playerAllyAddr, playerPoints, rankPoints, rankBattle) = False) Then
                        Exit For
                    End If
                Next
                Return True
            Catch Exception As Exception
                Return False
            End Try
        End Function

        Public Function OpSrvRetrieveUserDetails(ByRef s_cookies As CookieContainer, ByVal OpRetrieveUserDetailsCallback As OpRetrieveUserDetails, ByVal playerProfileAddr As String) As Boolean
            Try
                Dim playerPointsRanking As UShort
                Dim playerBattleRanking As Short
                Dim playerName As String
                Dim playerMail As String
                Dim playerPage As String
                Dim playerCountry As String
                Dim playerGameCountry As String
                Dim playerCoords As String
                Dim playerWinBattles As UShort
                Dim playerLostBattles As UShort
                Dim playerAllyFullname As String
                Dim playerFactories As String
                Dim playerMines As String
                Dim playerRefineries As String
                Dim playerLoot As UShort
                Dim playerPoints As String
                Dim playerBattlePoints As String
                Dim playerOnline As Boolean
                Dim playerLocked As Boolean
                Dim playerHoliday As Boolean
                Dim playerBlocked As Boolean
                Dim d_response As String
                Using d_get As New Ajax(playerProfileAddr, System.Text.Encoding.Unicode, s_cookies, AjaxType.AjaxPOST)
                    d_response = d_get.Send(String.Empty)
                End Using
                Dim htmlDoc As New HtmlDocument
                htmlDoc.LoadHtml(d_response)
                Dim userDetailsNodes As HtmlNodeCollection = htmlDoc.DocumentNode.SelectSingleNode("//table[@class='userDetails']").SelectNodes("tr")
                Dim userpPage As HtmlNode = userDetailsNodes(1).SelectNodes("td")(1).SelectSingleNode("a")
                If (userpPage IsNot Nothing) Then
                    playerMail = Replace(userpPage.Attributes("href").Value, "mailto:", String.Empty)
                Else
                    playerMail = String.Empty
                End If
                Dim userpCountry As HtmlNode = userDetailsNodes(2).SelectNodes("td")(1).SelectSingleNode("a")
                If (userpCountry IsNot Nothing) Then
                    playerPage = userpCountry.Attributes("href").Value
                Else
                    playerPage = String.Empty
                End If
                playerCountry = userDetailsNodes(3).SelectNodes("td")(1).InnerText
                playerGameCountry = userDetailsNodes(5).SelectNodes("td")(1).InnerText
                playerCoords = userDetailsNodes(6).SelectNodes("td")(1).InnerText
                Dim incNode As UShort = 0
                If (userDetailsNodes(7).SelectNodes("td")(1).InnerText.Contains("%") <> True) Then
                    incNode += 1
                End If
                Dim strWinBattles As String = userDetailsNodes(7 + incNode).SelectNodes("td")(1).InnerText
                Dim strTmpWinBattles As String = String.Empty
                Dim bFirst As Boolean = True
                For char_i As UShort = 0 To strWinBattles.Length - 1
                    If (IsNumeric(strWinBattles(char_i)) = True) Then
                        strTmpWinBattles &= strWinBattles(char_i)
                    Else
                        If (bFirst = False) Then
                            playerWinBattles = CUShort(strTmpWinBattles)
                            Exit For
                        Else
                            bFirst = False
                        End If
                    End If
                Next
                Dim strLostBattles As String = userDetailsNodes(8 + incNode).SelectNodes("td")(1).InnerText
                Dim strTmpLostBattles As String = String.Empty
                Dim bFirst_2 As Boolean = True
                For char_i As UShort = 0 To strLostBattles.Length - 1
                    If (IsNumeric(strLostBattles(char_i)) = True) Then
                        strTmpLostBattles &= strLostBattles(char_i)
                    Else
                        If (bFirst_2 = False) Then
                            playerLostBattles = CUShort(strTmpLostBattles)
                            Exit For
                        Else
                            bFirst_2 = False
                        End If
                    End If
                Next
                playerAllyFullname = userDetailsNodes(9 + incNode).SelectNodes("td")(1).InnerText
                If (incNode = 1) Then
                    If (userDetailsNodes.Count = 20) Then
                        incNode += 1
                    End If
                Else
                    If (userDetailsNodes.Count = 19) Then
                        incNode += 1
                    End If
                End If
                playerFactories = userDetailsNodes(12 + incNode).SelectNodes("td")(1).SelectSingleNode("span").Attributes("data").Value
                playerMines = userDetailsNodes(13 + incNode).SelectNodes("td")(1).SelectSingleNode("span").Attributes("data").Value
                playerRefineries = userDetailsNodes(14 + incNode).SelectNodes("td")(1).SelectSingleNode("span").Attributes("data").Value
                playerLoot = CUShort(Replace(userDetailsNodes(15 + incNode).SelectNodes("td")(1).InnerText, "%", String.Empty))
                Dim pointsNodes As HtmlNodeCollection = userDetailsNodes(16 + incNode).SelectNodes("td")(1).SelectNodes("span")
                playerPoints = pointsNodes(0).Attributes("data").Value
                playerBattlePoints = pointsNodes(1).Attributes("data").Value
                Dim playerNameNode As HtmlNode = htmlDoc.DocumentNode.SelectSingleNode("//h1[contains(@class, 'main')]")
                Dim imgNode As HtmlNode = playerNameNode.SelectSingleNode("img")
                playerName = playerNameNode.InnerText
                If (imgNode IsNot Nothing) Then
                    If (imgNode.Attributes("src").Value.Contains("weather_sun")) Then
                        playerHoliday = True
                    Else
                        playerHoliday = False
                    End If
                    If (imgNode.Attributes("src").Value.Contains("bullet_green")) Then
                        playerOnline = True
                    Else
                        playerOnline = False
                    End If
                    If (imgNode.Attributes("src").Value.Contains("lock_go")) Then
                        playerLocked = True
                    Else
                        playerLocked = False
                    End If
                    If (imgNode.Attributes("src").Value.Contains("lock.png")) Then
                        playerBlocked = True
                    Else
                        playerBlocked = False
                    End If
                Else
                    playerHoliday = False
                    playerOnline = False
                    playerLocked = False
                    playerBlocked = False
                End If
                Dim divNode As HtmlNode = htmlDoc.DocumentNode.SelectSingleNode("//div[@id='hsRanks']")
                If (divNode IsNot Nothing) Then
                    Dim prankPos As String = divNode.SelectSingleNode("h1").InnerText.Trim
                    Dim brankPos As String = divNode.SelectSingleNode("h2").InnerText.Trim
                    If (prankPos = "#") Then
                        playerPointsRanking = 0
                    Else
                        playerPointsRanking = CUShort(Replace(prankPos, "#", String.Empty))
                    End If
                    If (brankPos = "-") Then
                        playerBattleRanking = -1
                    Else
                        playerBattleRanking = CShort(Replace(brankPos, "#", String.Empty))
                    End If
                End If
                OpRetrieveUserDetailsCallback(playerName, playerMail, playerCountry, playerGameCountry, playerCoords, playerWinBattles, playerLostBattles, playerAllyFullname, playerFactories, playerMines, playerRefineries, playerLoot, playerPoints, playerBattlePoints, playerOnline, playerLocked, playerHoliday, playerBlocked, playerPointsRanking, playerBattleRanking)
                Return True
            Catch Exception As Exception
                Return False
            End Try
        End Function

        Public Function OpSrvAuth0(ByVal usersHash As String, ByVal landId As String, ByVal OpRemoteAddr As String) As CookieContainer
            Dim s_cookies As New CookieContainer
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("PHPSESSID", "e0fb92dfe2bb45967a374a0dc491318e"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("__utma", "109989082.412957457.1547752233.1549230383.1549230383.1"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("__utmz", "109989082.1549230383.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none)"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("_ga", "GA1.2.412957457.1547752233"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("_gcl_au", "1.1.1224744113.1547752233"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("_gid", "GA1.2.1311796503.1548895969"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("apples", "16-447429-1550229794"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("applesc", "16-447429-1550229794"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("applesc", "16-447429-1550229794"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("applesd", "16-447429-1550229794"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("applesd", "16-447429-1550229794"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("gamigo", "e3c2f02de8acf2a1bdfd097c6b202247"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("gamigoCookie", "true"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("incap_ses_789_1694276", "HaVecuI0lk3kJb9uFRjzCjb7ZVwAAAAAEcBTqhys8bS6SNrttVIj9A=="))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("infopanel_tab_banner2", "up"))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("infopanel_tab_friends", "up"))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("infopanel_tab_help", "up"))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("infopanel_tab_noob", "up"))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("infopanel_tab_notes", "up"))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("infopanel_tab_quest", "up"))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("infopanel_tab_reports", "up"))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("ingamePollTab", "up"))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("isAppMobile", "1"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("notesTextAreaHeight", "181"))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("platform", "desktop"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("pt", "T1"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("ptm", "BOACOMPRA_BOLETO_BANCARIO"))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("rid", "0"))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("thisUsersHash", usersHash))
            s_cookies.Add(New Uri(OpRemoteAddr), New Cookie("thisUsersLandId", landId))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("visid_incap_1206213", "yCaUCeP6T0+8D0c5p/HyGiFhV1wAAAAAQUIPAAAAAABWU2eJgeHexYCNTEK6vBIY"))
            's_cookies.Add(New Uri(OpRemoteAddr), New Cookie("visid_incap_1694276", "0jE/HsgaTYy8i/cFSKug53dJTlwAAAAAQUIPAAAAAADWaT9RVtaRg8HI6NSWCmbV"))
            Return s_cookies
        End Function

        Public Function OpClntResources(ByRef s_cookies As CookieContainer, ByVal OpWorld As String, ByVal OpRemoteAddr As String) As OpClntUserResources
            Try
                Dim userResources As New OpClntUserResources
                Dim d_response As String
                Using d_get As New Ajax(OpRemoteAddr & "/" & OpWorld & "/Webservices/resourcebar.php", System.Text.Encoding.Unicode, s_cookies, AjaxType.AjaxGET)
                    d_response = d_get.Send("json=true")
                End Using
                Dim resBar As resourceBar = JsonConvert.DeserializeObject(Of resourceBar)(d_response)
                For Each resource As resources_t In resBar.resources
                    Select Case resource.resourceName
                        Case "oil"
                            userResources.Oil = resource.amount
                        Case "cerosin"
                            userResources.Cerosin = resource.amount
                        Case "diesel"
                            userResources.Diesel = resource.amount
                        Case "ammunition"
                            userResources.Ammunition = resource.amount
                        Case "money"
                            userResources.Money = resource.amount
                        Case "gold"
                            userResources.Gold = resource.amount
                        Case "diamonds"
                            userResources.Diamonds = resource.amount
                        Case "points"
                            userResources.Points = resource.amount
                    End Select
                Next
                Return userResources
            Catch WSockEx As Exception
                Return Nothing
            End Try
        End Function

        Public Function OpClntData(ByRef s_cookies As CookieContainer, ByVal OpWorld As String, ByVal OpRemoteAddr As String) As OpClntInternalData
            Dim d_response As String
            Using d_get As New Ajax(OpRemoteAddr & "/" & OpWorld & "/Webservices/getGamedata.php", System.Text.Encoding.Unicode, s_cookies, AjaxType.AjaxGET)
                d_response = d_get.Send("iQuestId=0&bSkipBuilding=false")
            End Using
            Dim internalData As internalOpData = JsonConvert.DeserializeObject(Of internalOpData)(d_response)
            Dim IFormat As IFormatProvider = New CultureInfo("en-US", True)
            Dim ClntIntrnlData As New OpClntInternalData
            With ClntIntrnlData
                .Version = internalData.GameVersion
                .PaymentHash = internalData.paymentHash
                .User = New OpClntUser
                .User.Username = internalData.user.name
                .User.Land = internalData.user.land
                .User.Rank = internalData.user.rank
                .User.Alliance = internalData.user.alliance
                .Weather = New OpClntWeather
                .Weather.Min = internalData.weather.min
                .Weather.Max = internalData.weather.max
                .Weather.Id = internalData.weather.id
                .Weather.Name = internalData.weather.name
                .Weather.EndDate = DateTime.ParseExact(internalData.weather.expire, "dd.MM.yy HH:mm", IFormat)
                If (internalData.allianceattacks IsNot Nothing And IsNumeric(internalData.allianceattacks)) Then .Attacks = CUShort(internalData.allianceattacks)
            End With
            Dim OpBuildings As New List(Of OpClntBuilding)
            Dim OpCurrtBuilding As New OpClntBuilding
            If (internalData.buildings._1.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._1.htmlid
            If (internalData.buildings._1.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._1.state
            If (internalData.buildings._1.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._1.amount
            If (internalData.buildings._1.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._1.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._2.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._2.htmlid
            If (internalData.buildings._2.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._2.state
            If (internalData.buildings._2.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._2.amount
            If (internalData.buildings._2.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._2.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._3.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._3.htmlid
            If (internalData.buildings._3.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._3.state
            If (internalData.buildings._3.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._3.amount
            If (internalData.buildings._3.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._3.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._4.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._4.htmlid
            If (internalData.buildings._4.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._4.state
            If (internalData.buildings._4.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._4.amount
            If (internalData.buildings._4.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._4.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._8.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._8.htmlid
            If (internalData.buildings._8.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._8.state
            If (internalData.buildings._8.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._8.amount
            If (internalData.buildings._8.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._8.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._10.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._10.htmlid
            If (internalData.buildings._10.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._10.state
            If (internalData.buildings._10.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._10.amount
            If (internalData.buildings._10.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._10.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._18.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._18.htmlid
            If (internalData.buildings._18.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._18.state
            If (internalData.buildings._18.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._18.amount
            If (internalData.buildings._18.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._18.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._19.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._19.htmlid
            If (internalData.buildings._19.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._19.state
            If (internalData.buildings._19.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._19.amount
            If (internalData.buildings._19.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._19.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._20.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._20.htmlid
            If (internalData.buildings._20.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._20.state
            If (internalData.buildings._20.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._20.amount
            If (internalData.buildings._20.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._20.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._21.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._21.htmlid
            If (internalData.buildings._21.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._21.state
            If (internalData.buildings._21.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._21.amount
            If (internalData.buildings._21.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._21.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._25.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._25.htmlid
            If (internalData.buildings._25.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._25.state
            If (internalData.buildings._25.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._25.amount
            If (internalData.buildings._25.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._25.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._26.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._26.htmlid
            If (internalData.buildings._26.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._26.state
            If (internalData.buildings._26.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._26.amount
            If (internalData.buildings._26.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._26.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._30.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._30.htmlid
            If (internalData.buildings._30.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._30.state
            If (internalData.buildings._30.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._30.amount
            If (internalData.buildings._30.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._30.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._31.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._31.htmlid
            If (internalData.buildings._31.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._31.state
            If (internalData.buildings._31.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._31.amount
            If (internalData.buildings._31.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._31.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._32.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._32.htmlid
            If (internalData.buildings._32.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._32.state
            If (internalData.buildings._32.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._32.amount
            If (internalData.buildings._32.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._32.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._33.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._33.htmlid
            If (internalData.buildings._33.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._33.state
            If (internalData.buildings._33.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._33.amount
            If (internalData.buildings._33.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._33.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._34.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._34.htmlid
            If (internalData.buildings._34.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._34.state
            If (internalData.buildings._34.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._34.amount
            If (internalData.buildings._34.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._34.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._38.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._38.htmlid
            If (internalData.buildings._38.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._38.state
            If (internalData.buildings._38.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._38.amount
            If (internalData.buildings._38.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._38.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._39.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._39.htmlid
            If (internalData.buildings._39.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._39.state
            If (internalData.buildings._39.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._39.amount
            If (internalData.buildings._39.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._39.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._40.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._40.htmlid
            If (internalData.buildings._40.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._40.state
            If (internalData.buildings._40.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._40.amount
            If (internalData.buildings._40.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._40.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._42.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._42.htmlid
            If (internalData.buildings._42.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._42.state
            If (internalData.buildings._42.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._42.amount
            If (internalData.buildings._42.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._42.title
            OpBuildings.Add(OpCurrtBuilding)
            OpCurrtBuilding = New OpClntBuilding
            If (internalData.buildings._43.htmlid IsNot Nothing) Then OpCurrtBuilding.Id = internalData.buildings._43.htmlid
            If (internalData.buildings._43.state IsNot Nothing) Then OpCurrtBuilding.State = internalData.buildings._43.state
            If (internalData.buildings._43.amount IsNot Nothing) Then OpCurrtBuilding.Amount = internalData.buildings._43.amount
            If (internalData.buildings._43.title IsNot Nothing) Then OpCurrtBuilding.Title = internalData.buildings._43.title
            OpBuildings.Add(OpCurrtBuilding)
            With ClntIntrnlData
                .Buildings = OpBuildings.ToArray()
            End With
            Dim OpClntTasks As New List(Of OpClntTask)
            For Each taskElem As task_t In internalData.tasks
                Dim POpClntTask As New OpClntTask
                With POpClntTask
                    If (taskElem.action IsNot Nothing) Then POpClntTask.Action = taskElem.action
                    If (taskElem.id IsNot Nothing) Then POpClntTask.Id = taskElem.id
                    If (taskElem.duration IsNot Nothing) Then POpClntTask.Duration = CULng(taskElem.duration)
                    If (taskElem.referenceId IsNot Nothing) Then POpClntTask.ReferenceId = taskElem.referenceId
                    If (taskElem.showCancel IsNot Nothing) Then If (taskElem.showCancel.ToUpper = "TRUE") Then POpClntTask.Cancelable = True Else POpClntTask.Cancelable = False
                    If (taskElem.isAttacker IsNot Nothing) Then If (taskElem.isAttacker.ToUpper = "TRUE") Then POpClntTask.Attacking = True Else POpClntTask.Attacking = False
                    If (taskElem.text IsNot Nothing) Then POpClntTask.Text = taskElem.text
                    If (taskElem.weaponName IsNot Nothing) Then POpClntTask.WeaponName = taskElem.weaponName
                    If (taskElem.weaponAmount IsNot Nothing) Then POpClntTask.WeaponAmount = taskElem.weaponAmount
                    If (taskElem.order IsNot Nothing) Then POpClntTask.Order = taskElem.order
                    If (taskElem.opponent IsNot Nothing) Then POpClntTask.OpponentHash = taskElem.opponent
                    If (taskElem.opponentName IsNot Nothing) Then POpClntTask.OpponentName = taskElem.opponentName
                    If (taskElem.name IsNot Nothing) Then POpClntTask.Name = taskElem.name

                    If (taskElem.type IsNot Nothing) Then POpClntTask.Type = taskElem.type
                    If (taskElem.text IsNot Nothing) Then POpClntTask.Text = taskElem.text
                    If (taskElem.action IsNot Nothing) Then POpClntTask.Action = taskElem.action
                End With
                OpClntTasks.Add(POpClntTask)
            Next
            ClntIntrnlData.Tasks = OpClntTasks.ToArray()
            Return ClntIntrnlData
        End Function

        Public Sub OpSrvUpdateInfo(ByRef s_cookies As CookieContainer, ByVal OpWorld As String, ByVal OpRemoteAddr As String, ByVal startIndex As UShort, ByVal endIndex As UShort, ByVal OpProgressCallback As OpSrvUpdateProgress, ByVal binaryFile As String)
            Dim EngWorker As New EngOpSrvUpd
            EngWorker.EngOpAuthCookies = s_cookies
            EngWorker.EngOpSrvTotalUsers = (endIndex - startIndex) + 1
            EngWorker.EngOpUpdateProgress = OpProgressCallback
            If (File.Exists(binaryFile) = False) Then
                File.Create(binaryFile).Close()
            End If
            If (FileLen(binaryFile) > 0) Then
                Dim BinFormatter As New BinaryFormatter()
                Using fStream As New FileStream(binaryFile, FileMode.Open, FileAccess.Read, FileShare.Read, 4096)
                    EngWorker.EngOpSrvScheme = DirectCast(BinFormatter.Deserialize(fStream), OpSrvInformationScheme)
                End Using
            Else
                EngWorker.EngOpSrvScheme = New OpSrvInformationScheme
                EngWorker.EngOpSrvScheme.Players = New List(Of OpSrvUserInfo)
            End If
            If (OpSrvRetrieveUsers(s_cookies, AddressOf EngWorker.OpRetrieveUsersCallback, startIndex, endIndex, OpWorld, OpRemoteAddr) <> True) Then
                Throw New Exception("Information scheme of server failed to start...")
            Else
                Dim BinFormatter As New BinaryFormatter()
                Using fStream As New FileStream(binaryFile, FileMode.Open, FileAccess.ReadWrite, FileShare.Read, 4096)
                    fStream.Seek(0, SeekOrigin.Begin)
                    fStream.SetLength(0)
                    fStream.Flush()
                    BinFormatter.Serialize(fStream, EngWorker.EngOpSrvScheme)
                End Using
            End If
        End Sub

        Public Sub OpOrderSrvUserByRanking0(ByRef OpSrvUsers As List(Of OpSrvUserInfo))
            Dim nOpSrvUsers As New List(Of OpSrvUserInfo)
            Dim flag As UShort = 0
            Dim minRank As UShort = 0
            Dim maxRank As UShort = 0
            While (flag < OpSrvUsers.Count)
                If (minRank = 0) Then
                    minRank = OpSrvUsers(flag).PlayerPointsRanking
                    flag += 1
                Else
                    If (OpSrvUsers(flag).PlayerPointsRanking < minRank) Then
                        minRank = OpSrvUsers(flag).PlayerPointsRanking
                    End If
                    flag += 1
                End If
            End While
            flag = 0
            While (flag < OpSrvUsers.Count)
                If (maxRank = 0) Then
                    maxRank = OpSrvUsers(flag).PlayerPointsRanking
                    flag += 1
                Else
                    If (OpSrvUsers(flag).PlayerPointsRanking > maxRank) Then
                        maxRank = OpSrvUsers(flag).PlayerPointsRanking
                    End If
                    flag += 1
                End If
            End While
            Dim diff As UShort = minRank
            While (nOpSrvUsers.Count < maxRank)
                For i As UShort = 0 To OpSrvUsers.Count - 1
                    If (OpSrvUsers(i).PlayerPointsRanking = diff + nOpSrvUsers.Count) Then
                        nOpSrvUsers.Add(OpSrvUsers(i))
                        Exit For
                    End If
                Next
            End While
            OpSrvUsers = nOpSrvUsers
        End Sub

        Public Sub OpSrvUpdateResetLog0(ByRef OpSrvScheme As OpSrvInformationScheme)
            For pi As UShort = 0 To OpSrvScheme.Players.Count - 1
                Dim opUser As OpSrvUserInfo = OpSrvScheme.Players(pi)
                opUser.LastDefeats = Nothing
                opUser.LastTimeOnline = Nothing
                opUser.LastVictories = Nothing
                OpSrvScheme.Players(pi) = opUser
            Next
        End Sub

    End Class

End Namespace