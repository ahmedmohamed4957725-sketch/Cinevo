import express from "express";
import { register , login , logout , refresh } from "./auth.controller.js";


const router = express.Router();



router.post("/refresh", refresh);

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);

export default router;